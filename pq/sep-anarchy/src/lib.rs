//! SEP Anarchy Soroban Contract — PQ flavor (FRI / BN254).
//!
//! Mirrors `plonk/sep-anarchy/src/lib.rs` shape-for-shape:
//! - same `DataKey`, `Error`, `CommitmentEntry`, event types,
//! - same `create_group` / `update_commitment` / `verify_membership`
//!   entrypoints,
//! - same global-nullifier replay protection (SHA-256 of proof bytes),
//! - same per-tier VK lookup,
//! - same restricted-mode + admin model.
//!
//! Differences vs. PLONK flavor:
//! - Verifier reaches into `env.crypto_hazmat().poseidon2_permutation`
//!   (Soroban Protocol 26+ host primitive) with vendored Horizen
//!   Labs canonical Poseidon2-BN254-t3 constants, instead of the
//!   BLS12-381 pairing primitive.
//! - Field is BN254 Fr — same byte width as the PLONK flavor's
//!   BLS12-381 Fr (32 bytes BE), so PI shape is unchanged at the
//!   client API surface.
//! - Proof bytes are variable-length `Bytes` (FRI proofs scale with
//!   query count × layer count × Merkle path depth).
//!
//! ## Status
//!
//! **Phase 1 (crypto primitives) only.** The verifier today runs
//! the FRI low-degree test using audited host primitives — this
//! gives correct cryptographic foundations but does NOT yet check
//! AIR constraints. The batched-PCS layer that ties FRI to a
//! constraint system is the gating dependency for production
//! deployment; do not deploy this contract without it.

#![no_std]

extern crate alloc;
use alloc::vec::Vec as AllocVec;

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, Vec,
};

use fri_verifier::field;
use fri_verifier::verifier::verify as fri_verify;
use fri_verifier::vk_format::VK_LEN;

// ================================================================
// Constants
// ================================================================

const HISTORY_WINDOW: u32 = 64;
const LEDGER_THRESHOLD: u32 = 17_280;
const LEDGER_BUMP: u32 = 518_400;
const MAX_GROUPS_PER_TIER: u32 = 10_000;

/// Membership-circuit public inputs: `(commitment, epoch)`.
/// Each PI is one BN254 Fr (32 bytes BE) — same convention as the
/// PLONK flavor's BLS12-381 Fr PIs, so client code is symmetric.
const MEMBERSHIP_PI_COUNT: u32 = 2;
/// Update-circuit public inputs: `(c_old, epoch_old, c_new)`.
const UPDATE_PI_COUNT: u32 = 3;

/// Hard cap on accepted proof size. Bench params produce ~10 KB
/// proofs; production parameters (log_n≥20, ~80 queries) push
/// proofs into the hundreds of KB. The cap below allows up to
/// 256 KB — generous for bench, tighten before production.
const MAX_PROOF_BYTES: u32 = 256 * 1024;

#[cfg(test)]
fn tier_capacity(tier: u32) -> u32 {
    match tier {
        0 => 32,
        1 => 256,
        2 => 2048,
        _ => 0,
    }
}

// ================================================================
// Embedded baked VKs
// ================================================================
//
// Bench-scale verifying keys (log_n=6, num_layers=3, num_queries=8,
// blowup=2). The Phase 2 follow-up swaps these for circuit-bound
// VKs once the AIR + batched-PCS layer lands. Until then the
// `pcs_pinned_root` field below is a placeholder pattern, NOT a
// real preprocessed-trace commitment.

/// VK byte width (defined by `fri_verifier::vk_format::VK_LEN`):
/// 5 × u32 header + 4 × 32B BN254 Fr = 148 bytes.
const VK_FILE_LEN: usize = VK_LEN;

/// `omega_0` for our log_n=6 domain — primitive 64-th root of unity
/// in BN254: `5^((r-1)/64) mod r`.
const OMEGA_0_BE: [u8; 32] = [
    0x14, 0x18, 0x14, 0x4d, 0x5b, 0x08, 0x0f, 0xca,
    0xc2, 0x4c, 0xdb, 0x76, 0x49, 0xbd, 0xad, 0xf2,
    0x46, 0xa6, 0xcb, 0x24, 0x26, 0xe3, 0x24, 0xbe,
    0xdb, 0x94, 0xfb, 0x05, 0x11, 0x8f, 0x02, 0x3a,
];
/// `omega_0^{-1} mod r`.
const OMEGA_0_INV_BE: [u8; 32] = [
    0x26, 0x17, 0x7c, 0xf2, 0xb2, 0xa1, 0x3d, 0x3a,
    0x03, 0x5c, 0xdc, 0x75, 0x67, 0xa8, 0xa6, 0x76,
    0xd8, 0x03, 0x96, 0xec, 0x1d, 0x32, 0x13, 0xee,
    0x78, 0xce, 0x6a, 0x0b, 0x76, 0x3d, 0x69, 0x8f,
];
/// `2^{-1} mod r = (r+1)/2`.
const TWO_INV_BE: [u8; 32] = [
    0x18, 0x32, 0x27, 0x39, 0x70, 0x98, 0xd0, 0x14,
    0xdc, 0x28, 0x22, 0xdb, 0x40, 0xc0, 0xac, 0x2e,
    0x94, 0x19, 0xf4, 0x24, 0x3c, 0xdc, 0xb8, 0x48,
    0xa1, 0xf0, 0xfa, 0xc9, 0xf8, 0x00, 0x00, 0x01,
];

/// `pcs_pinned_root` placeholder — single BN254 Fr (= 32 bytes).
/// Production VKs carry the prover-baked Merkle root of the AIR's
/// preprocessed trace columns, distinct per circuit.
const PCS_PINNED_ROOT_BE: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

const MEMBERSHIP_VK_BYTES: [u8; VK_FILE_LEN] = build_vk_bytes(MEMBERSHIP_PI_COUNT);
const UPDATE_VK_BYTES: [u8; VK_FILE_LEN] = build_vk_bytes(UPDATE_PI_COUNT);

const VK_D5: &[u8] = &MEMBERSHIP_VK_BYTES;
const VK_D8: &[u8] = &MEMBERSHIP_VK_BYTES;
const VK_D11: &[u8] = &MEMBERSHIP_VK_BYTES;

const UPDATE_VK_D5: &[u8] = &UPDATE_VK_BYTES;
const UPDATE_VK_D8: &[u8] = &UPDATE_VK_BYTES;
const UPDATE_VK_D11: &[u8] = &UPDATE_VK_BYTES;

const fn build_vk_bytes(num_pi: u32) -> [u8; VK_FILE_LEN] {
    let mut b = [0u8; VK_FILE_LEN];
    // log_n = 6 → initial domain size 64.
    b[0] = 6;
    // num_layers = 3 → final layer size 8.
    b[4] = 3;
    // num_queries = 8.
    b[8] = 8;
    // num_pi: per-circuit BN254 Fr count (= number of `BytesN<32>`
    // public inputs at the contract surface).
    let pi = num_pi.to_le_bytes();
    b[12] = pi[0];
    b[13] = pi[1];
    b[14] = pi[2];
    b[15] = pi[3];
    // blowup_log = 1 (rate 1/2).
    b[16] = 1;
    // pcs_pinned_root: 32 BE bytes at offset 20..52.
    let mut i = 0;
    while i < 32 {
        b[20 + i] = PCS_PINNED_ROOT_BE[i];
        b[52 + i] = OMEGA_0_BE[i];
        b[84 + i] = OMEGA_0_INV_BE[i];
        b[116 + i] = TWO_INV_BE[i];
        i += 1;
    }
    b
}

fn membership_vk_for_tier(tier: u32) -> Option<&'static [u8]> {
    match tier {
        0 => Some(VK_D5),
        1 => Some(VK_D8),
        2 => Some(VK_D11),
        _ => None,
    }
}

fn update_vk_for_tier(tier: u32) -> Option<&'static [u8]> {
    match tier {
        0 => Some(UPDATE_VK_D5),
        1 => Some(UPDATE_VK_D8),
        2 => Some(UPDATE_VK_D11),
        _ => None,
    }
}

// ================================================================
// Errors
// ================================================================

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
    /// Group commitment — single BN254 Fr (32 bytes BE).
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
        caller.require_auth();

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
        if !is_canonical_pi(&env, &commitment) {
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

        let vk_bytes = membership_vk_for_tier(tier).ok_or(Error::InvalidTier)?;
        verify_fri_proof(&env, vk_bytes, &proof, &public_inputs)?;

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
        if !is_canonical_pi(&env, &c_new) {
            return Err(Error::InvalidCommitmentEncoding);
        }
        if proof.len() > MAX_PROOF_BYTES {
            return Err(Error::ProofTooLarge);
        }

        Self::check_proof_replay(&env, &proof)?;

        let vk_bytes = update_vk_for_tier(current.tier).ok_or(Error::InvalidTier)?;
        verify_fri_proof(&env, vk_bytes, &proof, &public_inputs)?;

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

        let vk_bytes = membership_vk_for_tier(state.tier).ok_or(Error::InvalidTier)?;
        match verify_fri_proof(&env, vk_bytes, &proof, &public_inputs) {
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
// FRI verification glue
// ================================================================

/// Decode `proof: Bytes` to a heap-allocated `Vec<u8>`, copy each
/// `BytesN<32>` PI into a `[u8; 32]` slot, and hand off to the
/// verifier crate.
fn verify_fri_proof(
    env: &Env,
    vk_bytes: &[u8],
    proof: &Bytes,
    public_inputs: &Vec<BytesN<32>>,
) -> Result<(), Error> {
    // Bytes → Vec<u8>.
    let mut proof_vec: AllocVec<u8> = AllocVec::with_capacity(proof.len() as usize);
    for b in proof.iter() {
        proof_vec.push(b);
    }

    // Pack PIs into a fixed-size buffer (max = update circuit's 3 PIs).
    let pi_count = public_inputs.len() as usize;
    if pi_count > MAX_VERIFIER_PI {
        return Err(Error::PublicInputsMismatch);
    }
    let mut pi_buf: [[u8; 32]; MAX_VERIFIER_PI] = [[0u8; 32]; MAX_VERIFIER_PI];
    for i in 0..pi_count {
        pi_buf[i] = public_inputs.get(i as u32).unwrap().to_array();
    }

    fri_verify(env, vk_bytes, &proof_vec, &pi_buf[..pi_count])
        .map_err(|_| Error::InvalidProof)
}

const MAX_VERIFIER_PI: usize = UPDATE_PI_COUNT as usize;

// ================================================================
// Encoding helpers
// ================================================================

/// `u64` → 32-byte big-endian (high 24 zero, low 8 the value).
fn be32_from_u64(env: &Env, value: u64) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    BytesN::from_array(env, &bytes)
}

/// Each PI (commitment / epoch / etc.) must be a canonical BN254 Fr.
/// Reject any byte sequence ≥ r at the contract surface so the
/// verifier can assume canonical inputs throughout.
fn is_canonical_pi(env: &Env, value: &BytesN<32>) -> bool {
    field::is_canonical_be(env, &value.to_array())
}

// Cross-check at compile time that the verifier-crate constants
// haven't drifted out from under the contract.
const _: () = {
    assert!(VK_LEN == 148, "fri_verifier::vk_format::VK_LEN drifted");
    assert!(
        MEMBERSHIP_PI_COUNT < UPDATE_PI_COUNT,
        "membership PI count must be smaller than update PI count"
    );
};
