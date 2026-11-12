//! SEP Anarchy Soroban Contract — PQ flavor (SHA-256 STARK).
//!
//! Mirrors `plonk/sep-anarchy/src/lib.rs` shape-for-shape:
//! - same `DataKey`, `Error`, `CommitmentEntry`, event types,
//! - same `create_group` / `update_commitment` / `verify_membership`
//!   entrypoints and public-input order,
//! - same global-nullifier replay protection (SHA-256 of proof bytes),
//! - same per-tier verifier selection, restricted-mode + admin model.
//!
//! Differences vs. PLONK flavor:
//! - Proofs are zero-knowledge STARKs verified by `pq/sha-fri`:
//!   Poseidon2-BabyBear-16 membership / update AIRs, SHA-256 Merkle
//!   commitments + Fiat–Shamir through the `sha256` host function,
//!   FRI. No pairing, no trusted setup; security rests on hashes only.
//! - Proof bytes are variable-length `Bytes` (~39 KB or ~76 KB depending
//!   on the security profile, see `PROFILE`).
//! - A commitment `BytesN<32>` is a Poseidon2 digest: 8 BabyBear limbs,
//!   each a canonical little-endian `u32`. Epoch public inputs stay
//!   32-byte big-endian `u64`, as in the PLONK flavor.
//!
//! ## Status
//!
//! Poseidon2 is Plonky3's canonical BabyBear-16 instance. Unaudited; see
//! `pq/sha-fri/README.md` for open items.

#![no_std]

extern crate alloc;
use alloc::vec::Vec as AllocVec;

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, IntoVal, Vec,
};

use sha_fri::air::{digest_from_bytes, Kind};
use sha_fri::hash::{Digest, Hasher};
use sha_fri::params::{deployment_params, Profile};

// ================================================================
// Constants
// ================================================================

const HISTORY_WINDOW: u32 = 64;
const LEDGER_THRESHOLD: u32 = 17_280;
const LEDGER_BUMP: u32 = 518_400;
const MAX_GROUPS_PER_TIER: u32 = 10_000;

/// Membership-circuit public inputs: `(commitment, epoch)`.
const MEMBERSHIP_PI_COUNT: u32 = 2;
/// Update-circuit public inputs: `(c_old, epoch_old, c_new)`.
const UPDATE_PI_COUNT: u32 = 3;

/// Hard cap on accepted proof size: the largest honest proof is ~76 KB
/// and a Soroban transaction is capped at 132 KB anyway.
const MAX_PROOF_BYTES: u32 = 128 * 1024;

/// Security profile baked into this build (see `sha_fri::params::Profile`).
/// Default: ~100 bits classical in the conservative Johnson regime. The
/// `conjectured` feature builds the ~100-bit-conjectured variant with
/// half the queries and roughly half the proof size. **Both are only ~50
/// bits against a quantum adversary**; `pq/sep-tyranny` uses the
/// post-quantum `Pq100` profile.
#[cfg(not(feature = "conjectured"))]
const PROFILE: Profile = Profile::Johnson100;
#[cfg(feature = "conjectured")]
const PROFILE: Profile = Profile::Conjectured100;

fn tier_depth(tier: u32) -> Option<u8> {
    match tier {
        0 => Some(5),
        1 => Some(8),
        2 => Some(11),
        _ => None,
    }
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Reserved3 = 3,
    GroupAlreadyExists = 4,
    GroupNotFound = 5,
    GroupInactive = 6,
    InvalidProof = 7,
    InvalidTier = 8,
    PublicInputsMismatch = 10,
    InvalidEpoch = 11,
    ProofReplay = 12,
    TierGroupLimitReached = 13,
    AdminOnly = 14,
    InvalidCommitmentEncoding = 15,
    ProofTooLarge = 16,
    GroupStillActive = 27,
}

// ================================================================
// Events
// ================================================================

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupCreated {
    #[topic]
    pub group_id: BytesN<32>,
    pub commitment: BytesN<32>,
    pub epoch: u64,
    pub tier: u32,
    pub member_count: u32,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentUpdated {
    #[topic]
    pub group_id: BytesN<32>,
    pub commitment: BytesN<32>,
    pub epoch: u64,
    pub timestamp: u64,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictedModeChanged {
    #[topic]
    pub admin: Address,
    pub restricted: bool,
    pub timestamp: u64,
}

// ================================================================
// Types
// ================================================================

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentEntry {
    /// Group commitment — Poseidon2-BabyBear digest (8 × u32 LE).
    pub commitment: BytesN<32>,
    pub epoch: u64,
    pub timestamp: u64,
    pub tier: u32,
    pub active: bool,
    pub member_count: u32,
}

// ================================================================
// Storage Keys
// ================================================================

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    RestrictedMode,
    Group(BytesN<32>),
    History(BytesN<32>),
    UsedProof(BytesN<32>),
    GroupCount(u32),
}

// ================================================================
// Contract
// ================================================================

#[contract]
pub struct PqSepAnarchyContract;

#[contractimpl]
impl PqSepAnarchyContract {
    pub fn __constructor(env: Env, admin: Address) -> Result<(), Error> {
        Self::do_initialize(&env, admin)
    }

    fn do_initialize(env: &Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        Ok(())
    }

    pub fn set_restricted_mode(env: Env, restricted: bool) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::RestrictedMode, &restricted);

        let timestamp = env.ledger().timestamp();
        RestrictedModeChanged {
            admin,
            restricted,
            timestamp,
        }
        .publish(&env);
        Ok(())
    }

    pub fn bump_group_ttl(env: Env, group_id: BytesN<32>) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        if !Self::group_exists(&env, &group_id) {
            return Err(Error::GroupNotFound);
        }
        Self::bump_group(&env, &group_id);
        Ok(())
    }

    pub fn create_group(
        env: Env,
        caller: Address,
        group_id: BytesN<32>,
        commitment: BytesN<32>,
        tier: u32,
        member_count: u32,
        proof: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        // Authorize everything except the proof. Plain `require_auth()`
        // copies every argument into the auth entry, so the ~70-76 KB
        // proof would ride in the transaction twice and break the
        // 132 KB tx limit. The proof needs no signature: verification
        // binds it to `commitment`, and replay protection pins it to
        // one use.
        caller.require_auth_for_args(
            (group_id.clone(), commitment.clone(), tier, member_count).into_val(&env),
        );

        let restricted: bool = env
            .storage()
            .instance()
            .get(&DataKey::RestrictedMode)
            .unwrap_or(false);
        if restricted {
            let admin: Address = env
                .storage()
                .instance()
                .get(&DataKey::Admin)
                .ok_or(Error::NotInitialized)?;
            if caller != admin {
                return Err(Error::AdminOnly);
            }
        }

        if tier > 2 {
            return Err(Error::InvalidTier);
        }
        if !is_canonical_digest(&commitment) {
            return Err(Error::InvalidCommitmentEncoding);
        }
        if public_inputs.len() != MEMBERSHIP_PI_COUNT {
            return Err(Error::PublicInputsMismatch);
        }
        if public_inputs.get(0).unwrap() != commitment {
            return Err(Error::PublicInputsMismatch);
        }
        if public_inputs.get(1).unwrap() != be32_from_u64(&env, 0) {
            return Err(Error::PublicInputsMismatch);
        }
        if Self::group_exists(&env, &group_id) {
            return Err(Error::GroupAlreadyExists);
        }
        if proof.len() > MAX_PROOF_BYTES {
            return Err(Error::ProofTooLarge);
        }

        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::GroupCount(tier))
            .unwrap_or(0);
        if count >= MAX_GROUPS_PER_TIER {
            return Err(Error::TierGroupLimitReached);
        }

        Self::check_proof_replay(&env, &proof)?;

        verify_stark(&env, Kind::Membership, tier, &proof, &public_inputs, 0)?;

        Self::record_proof(&env, &proof);

        let timestamp = env.ledger().timestamp();
        let entry = CommitmentEntry {
            commitment: commitment.clone(),
            epoch: 0,
            timestamp,
            tier,
            active: true,
            member_count,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Group(group_id.clone()), &entry);
        env.storage().persistent().set(
            &DataKey::History(group_id.clone()),
            &Vec::<CommitmentEntry>::new(&env),
        );
        env.storage()
            .instance()
            .set(&DataKey::GroupCount(tier), &(count + 1));
        Self::bump_group(&env, &group_id);

        GroupCreated {
            group_id,
            commitment,
            epoch: 0,
            tier,
            member_count,
            timestamp,
        }
        .publish(&env);
        Ok(())
    }

    pub fn update_commitment(
        env: Env,
        group_id: BytesN<32>,
        proof: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<(), Error> {
        Self::require_initialized(&env)?;

        let current = Self::load_group(&env, &group_id)?;
        if !current.active {
            return Err(Error::GroupInactive);
        }
        let new_epoch = current.epoch.checked_add(1).ok_or(Error::InvalidEpoch)?;

        if public_inputs.len() != UPDATE_PI_COUNT {
            return Err(Error::PublicInputsMismatch);
        }
        let c_old = public_inputs.get(0).unwrap();
        let epoch_old_be = public_inputs.get(1).unwrap();
        let c_new = public_inputs.get(2).unwrap();

        if c_old != current.commitment {
            return Err(Error::PublicInputsMismatch);
        }
        if epoch_old_be != be32_from_u64(&env, current.epoch) {
            return Err(Error::PublicInputsMismatch);
        }
        if !is_canonical_digest(&c_new) {
            return Err(Error::InvalidCommitmentEncoding);
        }
        if proof.len() > MAX_PROOF_BYTES {
            return Err(Error::ProofTooLarge);
        }

        Self::check_proof_replay(&env, &proof)?;

        verify_stark(&env, Kind::Update, current.tier, &proof, &public_inputs, current.epoch)?;

        Self::record_proof(&env, &proof);

        let timestamp = env.ledger().timestamp();
        Self::archive_entry(&env, &group_id, &current);

        let new_entry = CommitmentEntry {
            commitment: c_new.clone(),
            epoch: new_epoch,
            timestamp,
            tier: current.tier,
            active: true,
            member_count: current.member_count,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Group(group_id.clone()), &new_entry);
        Self::bump_group(&env, &group_id);

        CommitmentUpdated {
            group_id,
            commitment: c_new,
            epoch: new_epoch,
            timestamp,
        }
        .publish(&env);
        Ok(())
    }

    pub fn verify_membership(
        env: Env,
        group_id: BytesN<32>,
        proof: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<bool, Error> {
        Self::require_initialized(&env)?;
        let state = Self::load_group(&env, &group_id)?;

        if public_inputs.len() != MEMBERSHIP_PI_COUNT {
            return Err(Error::PublicInputsMismatch);
        }
        if public_inputs.get(0).unwrap() != state.commitment {
            return Err(Error::PublicInputsMismatch);
        }
        if public_inputs.get(1).unwrap() != be32_from_u64(&env, state.epoch) {
            return Err(Error::PublicInputsMismatch);
        }
        if proof.len() > MAX_PROOF_BYTES {
            return Err(Error::ProofTooLarge);
        }

        match verify_stark(&env, Kind::Membership, state.tier, &proof, &public_inputs, state.epoch) {
            Ok(()) => Ok(true),
            Err(Error::InvalidProof) => Ok(false),
            Err(other) => Err(other),
        }
    }

    pub fn get_commitment(
        env: Env,
        group_id: BytesN<32>,
    ) -> Result<CommitmentEntry, Error> {
        Self::load_group(&env, &group_id)
    }

    pub fn get_history(
        env: Env,
        group_id: BytesN<32>,
        max_entries: u32,
    ) -> Result<Vec<CommitmentEntry>, Error> {
        if !Self::group_exists(&env, &group_id) {
            return Err(Error::GroupNotFound);
        }
        let history: Vec<CommitmentEntry> = env
            .storage()
            .persistent()
            .get(&DataKey::History(group_id))
            .unwrap_or(Vec::new(&env));
        let cap = if max_entries < history.len() {
            max_entries
        } else {
            history.len()
        };
        if cap == history.len() {
            return Ok(history);
        }
        let start = history.len() - cap;
        let mut result = Vec::new(&env);
        for i in start..history.len() {
            result.push_back(history.get(i).unwrap());
        }
        Ok(result)
    }

    fn require_initialized(env: &Env) -> Result<(), Error> {
        if !env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        Ok(())
    }

    fn load_group(env: &Env, group_id: &BytesN<32>) -> Result<CommitmentEntry, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Group(group_id.clone()))
            .ok_or(Error::GroupNotFound)
    }

    fn group_exists(env: &Env, group_id: &BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Group(group_id.clone()))
    }

    fn bump_group(env: &Env, group_id: &BytesN<32>) {
        if env
            .storage()
            .persistent()
            .has(&DataKey::Group(group_id.clone()))
        {
            env.storage().persistent().extend_ttl(
                &DataKey::Group(group_id.clone()),
                LEDGER_THRESHOLD,
                LEDGER_BUMP,
            );
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::History(group_id.clone()))
        {
            env.storage().persistent().extend_ttl(
                &DataKey::History(group_id.clone()),
                LEDGER_THRESHOLD,
                LEDGER_BUMP,
            );
        }
    }

    fn proof_hash(env: &Env, proof: &Bytes) -> BytesN<32> {
        env.crypto().sha256(proof).into()
    }

    fn check_proof_replay(env: &Env, proof: &Bytes) -> Result<(), Error> {
        let hash = Self::proof_hash(env, proof);
        if env.storage().persistent().has(&DataKey::UsedProof(hash)) {
            return Err(Error::ProofReplay);
        }
        Ok(())
    }

    fn record_proof(env: &Env, proof: &Bytes) {
        let hash = Self::proof_hash(env, proof);
        env.storage()
            .persistent()
            .set(&DataKey::UsedProof(hash.clone()), &true);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::UsedProof(hash), LEDGER_THRESHOLD, LEDGER_BUMP);
    }

    fn archive_entry(env: &Env, group_id: &BytesN<32>, entry: &CommitmentEntry) {
        let mut history: Vec<CommitmentEntry> = env
            .storage()
            .persistent()
            .get(&DataKey::History(group_id.clone()))
            .unwrap_or(Vec::new(env));
        history.push_back(entry.clone());
        if history.len() > HISTORY_WINDOW {
            let mut pruned = Vec::new(env);
            let start = history.len() - HISTORY_WINDOW;
            for i in start..history.len() {
                pruned.push_back(history.get(i).unwrap());
            }
            history = pruned;
        }
        env.storage()
            .persistent()
            .set(&DataKey::History(group_id.clone()), &history);
    }
}

// ================================================================
// STARK verification glue
// ================================================================

/// Every hash the verifier asks for becomes one `sha256` host call.
struct HostSha256<'a>(&'a Env);

impl Hasher for HostSha256<'_> {
    fn hash_parts(&self, parts: &[&[u8]]) -> Digest {
        let mut buf = AllocVec::with_capacity(parts.iter().map(|p| p.len()).sum());
        for p in parts {
            buf.extend_from_slice(p);
        }
        self.0.crypto().sha256(&Bytes::from_slice(self.0, &buf)).to_array()
    }
}

/// Translate the contract-level PIs (`BytesN<32>` digests, 32-byte BE
/// epoch) into the verifier's wire format and verify against the
/// deployment parameters for `(kind, tier)`.
fn verify_stark(
    env: &Env,
    kind: Kind,
    tier: u32,
    proof: &Bytes,
    public_inputs: &Vec<BytesN<32>>,
    epoch: u64,
) -> Result<(), Error> {
    let depth = tier_depth(tier).ok_or(Error::InvalidTier)?;
    let params = deployment_params(kind, depth, PROFILE).to_bytes();

    let mut pi = AllocVec::with_capacity(72);
    pi.extend_from_slice(&public_inputs.get(0).unwrap().to_array());
    pi.extend_from_slice(&epoch.to_le_bytes());
    if kind == Kind::Update {
        pi.extend_from_slice(&public_inputs.get(2).unwrap().to_array());
    }

    sha_fri::verifier::verify(&HostSha256(env), &params, &proof.to_alloc_vec(), &pi)
        .map_err(|_| Error::InvalidProof)
}

// ================================================================
// Encoding helpers
// ================================================================

/// `u64` → 32-byte big-endian (high 24 zero, low 8 the value).
fn be32_from_u64(env: &Env, value: u64) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    BytesN::from_array(env, &bytes)
}

/// A commitment must be a canonical Poseidon2-BabyBear digest: eight
/// little-endian `u32` limbs, each below the BabyBear modulus.
fn is_canonical_digest(value: &BytesN<32>) -> bool {
    digest_from_bytes(&value.to_array()).is_some()
}

#[cfg(test)]
mod test;
