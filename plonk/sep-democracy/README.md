# sep-democracy

Per-type **private group** on Soroban with **K-of-N admin quorum** + hidden
member counts (an occupancy commitment) + a configurable threshold. Update
authorization is in-circuit at tier 0/1. Tier 2 is currently disabled for
create/update because its d=11 update circuit is only a simplified
single-signer fallback (an SRS-budget constraint, see Notes).

```
                  SEP-DEMOCRACY  —  K-of-N → π flow
                  ════════════════════════════════════

  ┌─────────────────────────────────────────────────────────────┐
  │  OFF-CHAIN PROVER  (pure Rust / arkworks; no host fns)      │
  └─────────────────────────────────────────────────────────────┘

      Admin signer 0 knows: sk₀          Admin signer 1 knows: sk₁
              │                                 │
          Poseidon                          Poseidon
              │                                 │
              ▼                                 ▼
            leaf₀                             leaf₁
              │                                 │
        Merkle path σ₀ᵏ                  Merkle path σ₁ᵏ
              │                                 │
              ╲                               ╱
                ╲                           ╱
              compute_merkle_root_gadget   ╱
              (active-conditional;          ╲
               masked when active = 0)        ╲
                              │
                              ▼
                  ROOT_OLD  (member tree root)
                              │
              ┌───────────────┴───────────────────┐
              │   K  =  Σ active_i                │
              │   K  ≥  threshold_numerator       │
              │     encoded as K = thresh + slack │
              │     with 2-bit ranges (so the     │
              │     practical threshold ceiling   │
              │     is K_MAX = 2)                 │
              │                                   │
              │   pairwise leaf_idx distinctness  │
              │     (anti-double-count)           │
              │   active prefix (active₁ ⇒ active₀)│
              └───────────────┬───────────────────┘
                              │
        count_old, count_new, salt_oc_old, salt_oc_new (witness)
                              │
              ┌───────────────┴────────────────────┐
              │  occ_old = Poseidon(count_old,     │
              │                     salt_oc_old)   │
              │  occ_new = Poseidon(count_new,     │
              │                     salt_oc_new)   │
              │  | count_new − count_old | ≤ 1     │
              │     enforced as                    │
              │     (Δ)(Δ−1)(Δ+1) = 0 over Fr      │
              └───────────────┬────────────────────┘
                              │
                              ▼
       3-level commitment chain (matches the update circuit):
                              │
       inner_X = Poseidon(ROOT_X, epoch_X)
       mid_X   = Poseidon(inner_X, salt_X)
       c_X     = Poseidon(mid_X, occ_X)
                              │
                              ▼
      witness:  sk₀, sk₁, σ₀, σ₁, leaf_idx, active, ROOT_old,
                ROOT_new, count_old, count_new, salt_oc_*,
                salt_old, salt_new
      public:   c_old, epoch_old, c_new, occ_old, occ_new,
                threshold_numerator                  (6 scalars)
                              │
                              ▼
              ┌─────────────────────────────────┐
              │   TurboPlonk circuit            │
              │   `democracy_update_quorum`     │
              │   (d=5 / d=8 only — see Notes)  │
              │   BLS12-381 + EF KZG SRS        │
              └──────────────┬──────────────────┘
                             │
                             ▼
                       π  (1601 bytes)
                             │
  ───────────────────────────┼─────────────────────  wire boundary
                             │
                             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  ON-CHAIN  SepDemocracyContract                             │
  └─────────────────────────────────────────────────────────────┘

   ┌──────────────────────────┐    ┌──────────────────────────────┐
   │   create_group           │    │   update_commitment          │
   │                          │    │                              │
   │   PI = (COMMITMENT, 0)   │    │   PI = (c_old, ep_old, c_new,│
   │   2 scalars              │    │          occ_old, occ_new,   │
   │                          │    │          threshold)          │
   │   • caller.require_auth  │    │   6 scalars                  │
   │   • tier ≤ 1             │    │                              │
   │   • threshold ∈ [1,100]  │    │   • NO require_auth          │
   │     (contract level —    │    │     (proof IS the auth)      │
   │     CIRCUIT enforces     │    │   • state.tier ≤ 1           │
   │     ≤ K_MAX = 2 in the   │    │   • c_old == state.commitment│
   │     quorum branch)       │    │   • ep_old == BE(state.epoch)│
   │                          │    │   • canonical Fr(c_new)      │
   │   • canonical Fr(comm)   │    │   • canonical Fr(occ_new)    │
   │   • canonical Fr(occ)    │    │   • occ_old == state.occ     │
   │   • PI[0] == comm arg    │    │   • threshold == BE(         │
   │   • PI[1] == BE(0)       │    │       state.threshold)       │
   │   • !group_exists        │    │     ↑ contract-supplied; the │
   │   • count < 10 000       │    │       caller can't lie about │
   │   • SHA256(π) ∉ UsedProof│    │       which threshold the    │
   │                          │    │       proof binds            │
   │   verify(π,              │    │   • state.active             │
   │     MEMBERSHIP_VK[tier], │    │   • SHA256(π) ∉ UsedProof    │
   │     PI)                  │    │                              │
   │   ↑ shared with anarchy  │    │   verify(π,                  │
   │                          │    │     UPDATE_VK[tier],         │
   │   record SHA256(π)       │    │     PI)                      │
   │   store CommitmentEntry  │    │                              │
   │     epoch  = 0           │    │   archive old → History (≤64)│
   │     active = true        │    │   store new entry            │
   │     occupancy = arg ⚠   │    │     epoch  += 1              │
   │     threshold = arg     │    │     commitment   = c_new      │
   │   record SHA256(π)       │    │     occupancy    = occ_new    │
   │   bump TTLs              │    │     threshold preserved       │
   └────────────┬─────────────┘    │   record SHA256(π); bump TTLs │
                │                  └────────────┬─────────────────┘
                ▼                               ▼
          GroupCreated                   CommitmentUpdated

   ┌──────────────────────────────────────────────────────────────┐
   │   verify_membership  (read-only)                             │
   │                                                              │
   │   PI = (commitment, epoch);  matches stored state;           │
   │   verify(π, MEMBERSHIP_VK[tier], PI);                        │
   │   does NOT consume nullifier (no SHA256 record).             │
   │                                                              │
   │   Returns Ok(true) on accept, Ok(false) on InvalidProof —    │
   │   no panic on rejection.                                     │
   └──────────────────────────────────────────────────────────────┘
```

```
            UPDATE-TIME ADMIN QUORUM — K_MAX = 2 admin signers
            ═══════════════════════════════════════════════════

  At update time the prover assembles K_MAX = 2 admin-signer slots.
  The active flags must form a strict prefix:  (active₀, active₁) ∈
  { (0,0), (1,0), (1,1) } — never (0,1).

       slot 0                                 slot 1
       ───────                                ───────
       sk₀                                    sk₁
       merkle_path_0[]                        merkle_path_1[]
       leaf_idx_0                             leaf_idx_1
       active₀ ∈ {0, 1}                       active₁ ∈ {0, 1}
                                              (active₁ ⇒ active₀)

       │                                      │
   Poseidon                              Poseidon
       │                                      │
       ▼                                      ▼
     leaf₀ = Poseidon(sk₀)               leaf₁ = Poseidon(sk₁)
       │                                      │
       └──── compute_merkle_root_gadget       └──── compute_merkle_root_gadget
                  │                                       │
                  ▼                                       ▼
              R₀ (computed)                          R₁ (computed)


     active-conditional gate per slot:
       active_i · (R_i − ROOT_OLD)  ==  0
     (R_i must equal ROOT_OLD when slot is active; free witness when
      inactive — so an inactive slot may carry any Merkle opening
      against any other root without breaking the gate)


     anti-double-count, for every pair (j, i) with i > j:
       active_j · active_i · is_equal(leaf_idx_j, leaf_idx_i) == 0
     (two active slots can't share a leaf — distinctness is on
      leaf_idx, not Poseidon(sk); relies on member-tree uniqueness
      established by the off-circuit tree builder)


     K = Σ active_i           K ≤ K_MAX = 2
     K ≥ threshold_numerator   threshold ∈ [0, 3]   slack ∈ [0, 3]
       encoded as K = threshold + slack
       both range-checked into 2 bits


  ┌─────────────────────────────────────────────────────────────┐
  │ TIER MAPPING                                                 │
  └─────────────────────────────────────────────────────────────┘

   tier 0 (Small)   d = 5    capacity 2⁵  =   32    quorum circuit ✓
   tier 1 (Medium)  d = 8    capacity 2⁸  =  256    quorum circuit ✓
   tier 2 (Large)   d = 11   capacity 2¹¹ = 2048    DISABLED for create/update
                                                    (fallback has no
                                                     in-circuit K-of-N quorum)
```

## Notes

- **`commitment` is a 3-level Poseidon at update time**: `c_X =
  Poseidon(Poseidon(Poseidon(ROOT_X, epoch_X), salt_X), occ_X)`. The
  `occ_X` factor lets the same root + salt produce different commitments
  across membership-count snapshots.
- **`update_commitment` carries no `require_auth`.** The K-of-N admin
  quorum proof is the authorization — any address can submit on behalf
  of the group. Replay protection via `UsedProof(SHA256(π))`.
- **`verify_membership` reuses the shared `vk-d{5,8,11}.bin`** from
  sep-anarchy. A 2-level commitment chain matches the on-chain
  representation read-back path; quorum semantics are an
  update-time-only concern.
- **Tier 2 disabled for create/update (issue [#12](https://github.com/onymchat/onym-contracts/issues/12))**: the K-of-N quorum circuit at depth 11
  blows the n=32,768 SRS ceiling. Under the EF KZG 2023 ceremony's
  published sizes there's no n=65,536 SRS to consume, so tier-2 updates
  would have to verify against the simplified single-signer circuit
  instead. Because that circuit does **not** in-circuit-enforce the
  quorum gate, `create_group` and `update_commitment` reject tier 2
  until a real d11 quorum circuit lands. `verify_membership` still keeps
  the d11 membership VK available for read-only verification of any
  already-existing tier-2 state.
- **Threshold semantics — absolute K, not percentage (issue
  [#14](https://github.com/onymchat/onym-contracts/issues/14))**:
  the contract validates `threshold_numerator ∈ [1, K_MAX]` where
  `K_MAX = 2`, matching the prover circuit's 2-bit threshold gate.
  Pre-fix the contract accepted `[1, 100]` as if percentage
  semantics were enforced in-circuit; they aren't, so calls with
  `threshold > K_MAX` would pre-validate at create but fail
  in-circuit at the next `update_commitment`, surfaced as
  `Error::InvalidProof`. The contract surface now honestly reflects
  what the circuit can satisfy. Promoting to ratio semantics
  (`K * 100 ≥ threshold_numerator · member_count`) requires a
  wider range gate + a multiplicative constraint and is deferred
  alongside the K_MAX > 2 work.
- **Create-side gaps (DO NOT SHIP user-visible)** per the contract's
  module-level "Status — simplified initial port" docstring:
   - `create_group` reuses anarchy's 2-PI membership VK, so
     `occupancy_commitment_initial` is **not bound by the proof to
     the committed `c`**. A caller can supply any canonical Fr as the
     initial occupancy commitment; from that point forward
     `update_commitment`'s `occ_old_pi == state.occupancy_commitment`
     check rests on a value the prover chose freely at create time.
   - The simplified create's commitment chain is 2-level
     (`Poseidon(Poseidon(root, 0), salt)`, anarchy-shape) while
     `update_commitment` expects 3-level (`...occ_old`). Those
     don't match for a freshly-created group's stored `c`, which
     means a real `create_group → update_commitment` lineage isn't
     end-to-end tested today. Same class of bug as `sep-oligarchy`'s
     pre-#214 state; tracked for the same fix pattern.
