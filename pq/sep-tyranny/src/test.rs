//! End-to-end contract tests with real Pq100 STARK proofs (tier 0, d=5).

extern crate std;

use super::*;
use sha_fri::air::{digest_to_bytes, Kind};
use sha_fri::field::F;
use sha_fri::hash::Sha2Hasher;
use sha_fri::prover;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Address, Bytes, BytesN, Env};

fn gid(seed: u64) -> [F; 8] {
    core::array::from_fn(|i| F::from_u64(seed * 16 + i as u64))
}

struct Bundle {
    group_id: [u8; 32],
    commitment: [u8; 32],
    admin_comm: [u8; 32],
    c_new: [u8; 32],
    create_proof: AllocVec<u8>,
    member_proof: AllocVec<u8>,
    update_proof: AllocVec<u8>,
}

/// Admin = member at `seed`; `group` picks the group id.
fn bundle(seed: u64, group: u64) -> Bundle {
    let g = gid(group);
    let admin = prover::with_admin(prover::random_witness(5, seed, 0), g);
    let pc = deployment_params(Kind::AdminCreate, 5, PROFILE);
    let create_proof = prover::prove(&Sha2Hasher, &pc, &admin, seed + 1);
    let pi = admin.public_inputs();

    let member = prover::random_witness(5, seed, 0);
    let pm = deployment_params(Kind::Membership, 5, PROFILE);
    let member_proof = prover::prove(&Sha2Hasher, &pm, &member, seed + 2);

    let upd = prover::with_admin(prover::with_random_update(prover::random_witness(5, seed, 0), seed), g);
    let pu = deployment_params(Kind::AdminUpdate, 5, PROFILE);
    let update_proof = prover::prove(&Sha2Hasher, &pu, &upd, seed + 3);
    let upi = upd.public_inputs();

    Bundle {
        group_id: digest_to_bytes(&g),
        commitment: digest_to_bytes(&pi.commitment),
        admin_comm: digest_to_bytes(&pi.admin.unwrap().0),
        c_new: digest_to_bytes(&upi.c_new.unwrap()),
        create_proof,
        member_proof,
        update_proof,
    }
}

fn setup() -> (Env, PqSepTyrannyContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.cost_estimate().budget().reset_unlimited();
    let admin = Address::generate(&env);
    let id = env.register(PqSepTyrannyContract, (admin.clone(),));
    let client = PqSepTyrannyContractClient::new(&env, &id);
    (env, client, admin)
}

fn b32(env: &Env, b: &[u8; 32]) -> BytesN<32> {
    BytesN::from_array(env, b)
}

fn create(env: &Env, client: &PqSepTyrannyContractClient, caller: &Address, b: &Bundle) {
    let (g, c, a) = (b32(env, &b.group_id), b32(env, &b.commitment), b32(env, &b.admin_comm));
    client.create_group(
        caller,
        &g,
        &c,
        &0,
        &a,
        &Bytes::from_slice(env, &b.create_proof),
        &vec![env, c.clone(), be32_from_u64(env, 0), a.clone(), g.clone()],
    );
}

#[test]
fn create_verify_update_lifecycle() {
    let (env, client, caller) = setup();
    let b = bundle(7, 1);
    create(&env, &client, &caller, &b);
    let (g, c, a) = (b32(&env, &b.group_id), b32(&env, &b.commitment), b32(&env, &b.admin_comm));
    assert_eq!(client.get_commitment(&g).commitment, c);
    assert_eq!(client.get_admin_commitment(&g), a);

    // Any member (here: the admin's membership proof) verifies.
    let mp = Bytes::from_slice(&env, &b.member_proof);
    assert!(client.verify_membership(&g, &mp, &vec![&env, c.clone(), be32_from_u64(&env, 0)]));

    let c_new = b32(&env, &b.c_new);
    client.update_commitment(
        &g,
        &Bytes::from_slice(&env, &b.update_proof),
        &vec![&env, c.clone(), be32_from_u64(&env, 0), c_new.clone(), a.clone(), g.clone()],
    );
    let entry = client.get_commitment(&g);
    assert_eq!(entry.commitment, c_new);
    assert_eq!(entry.epoch, 1);
}

#[test]
fn non_admin_update_is_rejected() {
    // A different member's update proof for the same commitment carries a
    // different admin commitment: the contract's PI check refuses it, and
    // a proof forged against the stored admin_comm can't verify.
    let (env, client, caller) = setup();
    let b = bundle(7, 1);
    create(&env, &client, &caller, &b);
    let other = bundle(8, 1);
    let (g, c, a) = (b32(&env, &b.group_id), b32(&env, &b.commitment), b32(&env, &b.admin_comm));
    let r = client.try_update_commitment(
        &g,
        &Bytes::from_slice(&env, &other.update_proof),
        &vec![&env, c.clone(), be32_from_u64(&env, 0), b32(&env, &other.c_new), b32(&env, &other.admin_comm), g.clone()],
    );
    assert_eq!(r, Err(Ok(Error::PublicInputsMismatch)));
    let r = client.try_update_commitment(
        &g,
        &Bytes::from_slice(&env, &other.update_proof),
        &vec![&env, c.clone(), be32_from_u64(&env, 0), b32(&env, &other.c_new), a.clone(), g.clone()],
    );
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn create_proof_is_bound_to_group_id() {
    // Reusing a create proof under another group id fails verification.
    let (env, client, caller) = setup();
    let b = bundle(7, 1);
    let other_g = b32(&env, &digest_to_bytes(&gid(2)));
    let (c, a) = (b32(&env, &b.commitment), b32(&env, &b.admin_comm));
    let r = client.try_create_group(
        &caller,
        &other_g,
        &c,
        &0,
        &a,
        &Bytes::from_slice(&env, &b.create_proof),
        &vec![&env, c.clone(), be32_from_u64(&env, 0), a.clone(), other_g.clone()],
    );
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn replayed_create_proof_is_rejected() {
    let (env, client, caller) = setup();
    let b = bundle(7, 1);
    create(&env, &client, &caller, &b);
    let r = client.try_create_group(
        &caller,
        &b32(&env, &b.group_id),
        &b32(&env, &b.commitment),
        &0,
        &b32(&env, &b.admin_comm),
        &Bytes::from_slice(&env, &b.create_proof),
        &vec![
            &env,
            b32(&env, &b.commitment),
            be32_from_u64(&env, 0),
            b32(&env, &b.admin_comm),
            b32(&env, &b.group_id),
        ],
    );
    assert!(matches!(r, Err(Ok(Error::GroupAlreadyExists)) | Err(Ok(Error::ProofReplay))));
}

#[test]
fn create_auth_covers_args_but_not_proof() {
    use soroban_sdk::testutils::{AuthorizedFunction, AuthorizedInvocation};
    use soroban_sdk::Symbol;
    let (env, client, caller) = setup();
    let b = bundle(7, 1);
    create(&env, &client, &caller, &b);
    let (g, c, a) = (b32(&env, &b.group_id), b32(&env, &b.commitment), b32(&env, &b.admin_comm));
    assert_eq!(
        env.auths(),
        std::vec![(
            caller.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    client.address.clone(),
                    Symbol::new(&env, "create_group"),
                    (g, c, 0u32, a).into_val(&env),
                )),
                sub_invocations: std::vec![],
            }
        )]
    );
}

#[test]
fn rejects_non_canonical_group_id() {
    let (env, client, caller) = setup();
    let bad = b32(&env, &[0xff; 32]);
    let b = bundle(7, 1);
    let (c, a) = (b32(&env, &b.commitment), b32(&env, &b.admin_comm));
    let r = client.try_create_group(
        &caller,
        &bad,
        &c,
        &0,
        &a,
        &Bytes::new(&env),
        &vec![&env, c.clone(), be32_from_u64(&env, 0), a.clone(), bad.clone()],
    );
    assert_eq!(r, Err(Ok(Error::InvalidCommitmentEncoding)));
}
