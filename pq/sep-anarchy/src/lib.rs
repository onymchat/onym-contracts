//! SEP Anarchy Soroban Contract — PQ flavor (FRI / Plonky3-shape).
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
//! - Verifier reaches into `env.crypto()` for the Poseidon2-W16 host
//!   primitive instead of the BLS12-381 host primitive.
//! - Proof bytes are a variable-length `Bytes` (FRI proof sizes scale
//!   with query count × layer count × Merkle path depth — they don't
//!   fit a single `BytesN<N>` cleanly across tiers).
//! - VKs are 64-byte FRI verifying keys, not the multi-KB PLONK VKs.
//! - Public inputs decompose `BytesN<32>` into 8 little-endian
//!   BabyBear elements per PI; the verifier flattens this to a
//!   `[[u8; 4]]` slice.
//!
//! See `fri-verifier` crate-level docs for the open-work list:
//! prover-side fixtures, batched-PCS layer, canonical Poseidon2
//! constants. Until those land, the verifier in this contract should
//! be treated as a skeleton — it will reject proofs malformed at the
//! byte/shape level, but a real ship-ready contract requires the
//! batched-PCS layer landing on top of `fri::verify_fri`.

#![no_std]

extern crate alloc;
use alloc::vec::Vec as AllocVec;

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    Address, Bytes, BytesN, Env, Vec,
};

use fri_verifier::verifier::verify as fri_verify;
use fri_verifier::vk_format::VK_LEN;

// ================================================================
// Constants
// ================================================================

const HISTORY_WINDOW: u32 = 64;
const LEDGER_THRESHOLD: u32 = 17_280;
const LEDGER_BUMP: u32 = 518_400;
const MAX_GROUPS_PER_TIER: u32 = 10_000;

/// Membership-circuit public inputs: `(commitment, epoch)` —
/// 2 × BytesN<32> at the contract surface, decomposed to
/// 2 × 8 = 16 BabyBear elements at the verifier surface.
const MEMBERSHIP_PI_COUNT: u32 = 2;
/// Update-circuit public inputs: `(c_old, epoch_old, c_new)`.
const UPDATE_PI_COUNT: u32 = 3;

/// Each `BytesN<32>` PI carries 8 BabyBear elements (4 bytes each, LE).
const BABYBEAR_ELEMENTS_PER_PI: usize = 8;
/// Total BabyBear elements the verifier sees for a membership proof.
const VERIFIER_PI_COUNT_MEMBERSHIP: usize =
    MEMBERSHIP_PI_COUNT as usize * BABYBEAR_ELEMENTS_PER_PI;
/// Total BabyBear elements the verifier sees for an update proof.
const VERIFIER_PI_COUNT_UPDATE: usize =
    UPDATE_PI_COUNT as usize * BABYBEAR_ELEMENTS_PER_PI;
/// Upper bound on the verifier-side PI buffer.
const MAX_VERIFIER_PI: usize = VERIFIER_PI_COUNT_UPDATE;

/// Hard cap on accepted proof size (bytes). FRI proofs scale with
/// `num_queries × num_layers × path_depth`; for the depth-15 large
/// tier with 80 queries, real proofs land around ~150 KB. The cap
/// here is generous; tighten before production once a prover lands.
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
// **Placeholders** until the PQ prover lands. Each VK is the byte
// shape `fri_verifier::vk_format::parse_vk_bytes` expects — 64 bytes,
// canonical-field-encoded — but the bytes themselves are a fixed
// pattern that does not correspond to any real circuit. They exist
// so the contract compiles and the per-tier dispatch is wired; once
// the prover ships real VKs, replace these `include_bytes!` paths
// with the `tests/fixtures/` entries (mirroring the PLONK flavor's
// pattern).

const VK_D5: &[u8] = &MEMBERSHIP_VK_BYTES;
const VK_D8: &[u8] = &MEMBERSHIP_VK_BYTES;
const VK_D11: &[u8] = &MEMBERSHIP_VK_BYTES;

const UPDATE_VK_D5: &[u8] = &UPDATE_VK_BYTES;
const UPDATE_VK_D8: &[u8] = &UPDATE_VK_BYTES;
const UPDATE_VK_D11: &[u8] = &UPDATE_VK_BYTES;

/// Bench-scale verifying keys. NOT a real circuit. The placeholder
/// numbers are chosen so a single FRI proof fits inside a Soroban
/// tx envelope (full Plonky3 params at log_n=15, num_queries=80
/// produce ~290 KB proofs that don't fit). When the PQ prover ships
/// a real circuit, replace `include_bytes!` of the
/// `fri-verifier/tests/fixtures/` files (mirroring the PLONK flavor).
///
/// Bench parameters:
///   * `log_n      = 6`  → initial domain size 64
///   * `num_layers = 3`  → final layer size 8 (after three folds)
///   * `num_queries = 8` → eight independent FRI queries per proof
///   * `blowup_log = 1`  → rate 1/2 (polynomial degree < 32)
///   * Membership: 16 BabyBear PIs (= 2 × `BytesN<32>`).
///   * Update:     24 BabyBear PIs (= 3 × `BytesN<32>`).
///
/// Field constants (BabyBear, p = 2^31 - 2^27 + 1):
///   * `omega_0     = 0x669D6090` — primitive 64-th root of unity:
///                                   `31^((p-1)/64) mod p`
///   * `omega_0_inv = 0x27785FBF` — `omega_0^{-1} mod p`
///   * `two_inv     = 0x3C000001` — `2^{-1} mod p = (p+1)/2`
///
/// `pcs_pinned_root` is the 8-lane Merkle root of the preprocessed
/// trace. For the bench placeholder it's a fixed `{1,2,…,8}` pattern
/// — real VKs will carry the prover-baked root of the AIR's constant
/// columns, distinct per circuit.
const MEMBERSHIP_VK_BYTES: [u8; VK_LEN] = build_vk_bytes(VERIFIER_PI_COUNT_MEMBERSHIP as u32);
const UPDATE_VK_BYTES: [u8; VK_LEN] = build_vk_bytes(VERIFIER_PI_COUNT_UPDATE as u32);

const fn build_vk_bytes(num_pi: u32) -> [u8; VK_LEN] {
    let mut b = [0u8; VK_LEN];
    // log_n = 6 → initial domain size 64.
    b[0] = 6;
    // num_layers = 3 → final layer size 8.
    b[4] = 3;
    // num_queries = 8.
    b[8] = 8;
    // num_pi: per-circuit BabyBear element count.
    let pi = num_pi.to_le_bytes();
    b[12] = pi[0];
    b[13] = pi[1];
    b[14] = pi[2];
    b[15] = pi[3];
    // blowup_log = 1 (rate 1/2).
    b[16] = 1;
    // pcs_pinned_root: 8 lanes, fixed `{1,2,…,8}` placeholder.
    let mut i = 0;
    while i < 8 {
        b[20 + i * 4] = (i as u8) + 1;
        i += 1;
    }
    // omega_0 = 0x669D6090 (LE). Primitive 64-th root of unity in
    // BabyBear, generated by `31^((p-1)/64) mod p`.
    b[52] = 0x90;
    b[53] = 0x60;
    b[54] = 0x9D;
    b[55] = 0x66;
    // omega_0_inv = 0x27785FBF (LE).
    b[56] = 0xBF;
    b[57] = 0x5F;
    b[58] = 0x78;
    b[59] = 0x27;
    // two_inv = 0x3C000001 (LE).
    b[60] = 0x01;
    b[61] = 0x00;
    b[62] = 0x00;
    b[63] = 0x3C;
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
    /// Group commitment — 8 BabyBear elements LE-packed into 32 bytes.
    pub commitment: BytesN<32>,
    pub epoch: u64,
    pub timestamp: u64,
    pub tier: u32,
    pub active: bool,
    /// Informational member count (not enforced; sentinel `0` =
    /// "not tracked"). Same convention as the PLONK flavor.
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

    /// Create a new Anarchy group at epoch 0.
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
        if !is_canonical_pi(&commitment) {
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

    /// Advance an Anarchy group to the next epoch.
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
        if !is_canonical_pi(&c_new) {
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

    // ---- Internal helpers ----

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

/// Decode `proof: Bytes` to a heap-allocated `Vec<u8>`, decompose
/// each `BytesN<32>` PI into its 8 BabyBear LE elements, hand off to
/// the verifier crate.
fn verify_fri_proof(
    env: &Env,
    vk_bytes: &[u8],
    proof: &Bytes,
    public_inputs: &Vec<BytesN<32>>,
) -> Result<(), Error> {
    // Bytes → Vec<u8>. The `alloc` feature is enabled in this
    // contract's Cargo.toml; `Bytes::iter` yields `u8`.
    let mut proof_vec: AllocVec<u8> = AllocVec::with_capacity(proof.len() as usize);
    for b in proof.iter() {
        proof_vec.push(b);
    }

    // Decompose `[BytesN<32>; n]` → `[[u8; 4]; 8 * n]`.
    let pi_count = public_inputs.len() as usize;
    let total = pi_count * BABYBEAR_ELEMENTS_PER_PI;
    if total > MAX_VERIFIER_PI {
        return Err(Error::PublicInputsMismatch);
    }
    let mut pi_buf: [[u8; 4]; MAX_VERIFIER_PI] = [[0u8; 4]; MAX_VERIFIER_PI];
    for i in 0..pi_count {
        let bn = public_inputs.get(i as u32).unwrap().to_array();
        for j in 0..BABYBEAR_ELEMENTS_PER_PI {
            let off = j * 4;
            pi_buf[i * BABYBEAR_ELEMENTS_PER_PI + j]
                .copy_from_slice(&bn[off..off + 4]);
        }
    }

    fri_verify(env, vk_bytes, &proof_vec, &pi_buf[..total])
        .map_err(|_| Error::InvalidProof)
}

// ================================================================
// Encoding helpers
// ================================================================

/// `u64` → 32-byte big-endian (high 24 zero, low 8 the value).
/// Same shape as the PLONK flavor's helper. Note: the PQ verifier
/// LE-decomposes this on the verifier side, so the on-chain BE
/// presentation here is mostly for client-API parity with the PLONK
/// flavor — clients can pass through the same bytes either way.
fn be32_from_u64(env: &Env, value: u64) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    BytesN::from_array(env, &bytes)
}

/// Each BabyBear element in a PI must be a canonical `[0, P)` `u32`.
/// Reject otherwise — `Fr::from_canonical_le_bytes` would do this on
/// the verifier side, but rejecting at the contract surface gives a
/// distinguishable error from a real `InvalidProof`.
fn is_canonical_pi(value: &BytesN<32>) -> bool {
    let bn = value.to_array();
    for j in 0..BABYBEAR_ELEMENTS_PER_PI {
        let off = j * 4;
        let v = u32::from_le_bytes([
            bn[off],
            bn[off + 1],
            bn[off + 2],
            bn[off + 3],
        ]);
        if v >= fri_verifier::field::P {
            return false;
        }
    }
    true
}

// Cross-check at compile time that the verifier-crate constants
// haven't drifted out from under the contract.
const _: () = {
    assert!(VK_LEN == 64, "fri_verifier::vk_format::VK_LEN drifted");
    assert!(
        BABYBEAR_ELEMENTS_PER_PI == 8,
        "BABYBEAR_ELEMENTS_PER_PI must be 8 (32-byte PI / 4-byte element)"
    );
    assert!(
        MAX_VERIFIER_PI == VERIFIER_PI_COUNT_UPDATE,
        "MAX_VERIFIER_PI must cover update circuit (3 PIs × 8 elements)"
    );
    assert!(
        VERIFIER_PI_COUNT_MEMBERSHIP < VERIFIER_PI_COUNT_UPDATE,
        "membership PI count must be smaller than update PI count"
    );
};
