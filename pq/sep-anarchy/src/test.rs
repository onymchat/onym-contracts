//! End-to-end contract tests with real STARK proofs (tier 0, d=5).

extern crate std;

use super::*;
use sha_fri::air::{digest_to_bytes, Kind};
use sha_fri::hash::Sha2Hasher;
use sha_fri::prover;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Address, Bytes, BytesN, Env};

struct Bundle {
    commitment: [u8; 32],
    c_new: [u8; 32],
    create_proof: AllocVec<u8>,
    update_proof: AllocVec<u8>,
}

fn bundle(seed: u64) -> Bundle {
    let member = prover::random_witness(5, seed, 0);
    let pm = deployment_params(Kind::Membership, 5, PROFILE);
    let create_proof = prover::prove(&Sha2Hasher, &pm, &member);
    let commitment = digest_to_bytes(&member.public_inputs().commitment);

    let upd = prover::with_random_update(prover::random_witness(5, seed, 0), seed);
    let pu = deployment_params(Kind::Update, 5, PROFILE);
    let update_proof = prover::prove(&Sha2Hasher, &pu, &upd);
    let c_new = digest_to_bytes(&upd.public_inputs().c_new.unwrap());
    Bundle { commitment, c_new, create_proof, update_proof }
}

fn setup() -> (Env, PqSepAnarchyContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let admin = Address::generate(&env);
    let id = env.register(PqSepAnarchyContract, (admin.clone(),));
    let client = PqSepAnarchyContractClient::new(&env, &id);
    (env, client, admin)
}

fn b32(env: &Env, b: &[u8; 32]) -> BytesN<32> {
    BytesN::from_array(env, b)
}

#[test]
fn create_verify_update_lifecycle() {
    let (env, client, admin) = setup();
    let b = bundle(7);
    let gid = b32(&env, &[0x50; 32]);
    let c = b32(&env, &b.commitment);
    let create_pi = vec![&env, c.clone(), be32_from_u64(&env, 0)];
    let create_proof = Bytes::from_slice(&env, &b.create_proof);

    client.create_group(&admin, &gid, &c, &0, &8, &create_proof, &create_pi);
    assert_eq!(client.get_commitment(&gid).commitment, c);
    assert!(client.verify_membership(&gid, &create_proof, &create_pi));

    // Replaying the create proof for a second group is rejected.
    let gid2 = b32(&env, &[0x51; 32]);
    assert_eq!(
        client.try_create_group(&admin, &gid2, &c, &0, &8, &create_proof, &create_pi),
        Err(Ok(Error::ProofReplay))
    );

    let c_new = b32(&env, &b.c_new);
    let update_pi = vec![&env, c.clone(), be32_from_u64(&env, 0), c_new.clone()];
    let update_proof = Bytes::from_slice(&env, &b.update_proof);
    client.update_commitment(&gid, &update_proof, &update_pi);
    let entry = client.get_commitment(&gid);
    assert_eq!(entry.commitment, c_new);
    assert_eq!(entry.epoch, 1);
    assert_eq!(client.get_history(&gid, &10).len(), 1);

    // The old membership proof no longer matches the group state.
    assert_eq!(
        client.try_verify_membership(&gid, &create_proof, &create_pi),
        Err(Ok(Error::PublicInputsMismatch))
    );
}

#[test]
fn rejects_tampered_create_proof() {
    let (env, client, admin) = setup();
    let b = bundle(9);
    let c = b32(&env, &b.commitment);
    let mut bad = b.create_proof.clone();
    let at = bad.len() - 100;
    bad[at] ^= 1;
    let r = client.try_create_group(
        &admin,
        &b32(&env, &[0x50; 32]),
        &c,
        &0,
        &8,
        &Bytes::from_slice(&env, &bad),
        &vec![&env, c.clone(), be32_from_u64(&env, 0)],
    );
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn rejects_proof_at_wrong_tier() {
    // A d=5 proof does not verify under the d=8 parameters.
    let (env, client, admin) = setup();
    let b = bundle(11);
    let c = b32(&env, &b.commitment);
    let r = client.try_create_group(
        &admin,
        &b32(&env, &[0x50; 32]),
        &c,
        &1,
        &8,
        &Bytes::from_slice(&env, &b.create_proof),
        &vec![&env, c.clone(), be32_from_u64(&env, 0)],
    );
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn rejects_non_canonical_commitment() {
    let (env, client, admin) = setup();
    let c = b32(&env, &[0xff; 32]);
    let r = client.try_create_group(
        &admin,
        &b32(&env, &[0x50; 32]),
        &c,
        &0,
        &8,
        &Bytes::new(&env),
        &vec![&env, c.clone(), be32_from_u64(&env, 0)],
    );
    assert_eq!(r, Err(Ok(Error::InvalidCommitmentEncoding)));
}

#[test]
fn create_auth_covers_args_but_not_proof() {
    use soroban_sdk::testutils::{AuthorizedFunction, AuthorizedInvocation};
    use soroban_sdk::{IntoVal, Symbol};
    let (env, client, admin) = setup();
    let b = bundle(13);
    let gid = b32(&env, &[0x52; 32]);
    let c = b32(&env, &b.commitment);
    client.create_group(
        &admin,
        &gid,
        &c,
        &0,
        &8,
        &Bytes::from_slice(&env, &b.create_proof),
        &vec![&env, c.clone(), be32_from_u64(&env, 0)],
    );
    assert_eq!(
        env.auths(),
        std::vec![(
            admin.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    client.address.clone(),
                    Symbol::new(&env, "create_group"),
                    (gid, c, 0u32, 8u32).into_val(&env),
                )),
                sub_invocations: std::vec![],
            }
        )]
    );
}
