# sep-oligarchy

Per-type **private group with two trees** (member + admin) on Soroban —
hidden member + admin counts via a salted occupancy commitment, configurable
admin quorum threshold, full **K-of-N admin authorization** + count-delta
enforcement in-circuit. The most security-load-bearing of the five contracts.

```
                  SEP-OLIGARCHY  —  K-of-N admin quorum flow
                  ═══════════════════════════════════════════

  ┌─────────────────────────────────────────────────────────────┐
  │  OFF-CHAIN PROVER  (pure Rust / arkworks; no host fns)      │
  └─────────────────────────────────────────────────────────────┘

      Admin signer 0:  sk₀                  Admin signer 1:  sk₁
              │                                     │
          Poseidon                              Poseidon
              │                                     │
              ▼                                     ▼
            leaf₀                                 leaf₁
              │                                     │
        Merkle path against            Merkle path against
        admin_root_old                 admin_root_old
        (admin tree, FIXED depth 5     (admin tree, FIXED depth 5
         per design §4.6 — admin       across all 3 member tiers)
         tier always Small)
              │                                     │
              ╲                                   ╱
                ╲                               ╱
              compute_merkle_root_gadget × 2   ╱
              (active-conditional;          ╲
               masked when active = 0)        ╲
                              │
                              ▼
                  admin_root_old
                              │
              ┌───────────────┴───────────────────┐
              │   K  =  Σ active_i                │
              │   K  ≥  admin_threshold_numerator │
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
        member_count_old, member_count_new,
        salt_oc_old, salt_oc_new   (witness)
                              │
              ┌───────────────┴────────────────────┐
              │  occ_old = Poseidon(member_count_  │
              │              old, salt_oc_old)     │
              │  occ_new = Poseidon(member_count_  │
              │              new, salt_oc_new)     │
              │  | count_new − count_old | ≤ 1     │
              │     enforced as                    │
              │     (Δ)(Δ−1)(Δ+1) = 0 over Fr      │
              │                                   │
              │  ⚠ count delta only — the         │
              │    member_root_new is a free      │
              │    witness; tree-level delta      │
              │    is deferred                    │
              └───────────────┬────────────────────┘
                              │
                              ▼
       3-level commitment chain (matches create + update + membership):
                              │
       inner_X    = Poseidon(member_root_X, epoch_X)
       mid_X      = Poseidon(inner_X, salt_X)
       admin_mix_X = Poseidon(occ_X, admin_root_X)
       c_X        = Poseidon(mid_X, admin_mix_X)
                              │
                              ▼
      witness:  sk₀, sk₁, σ₀, σ₁, leaf_idx, active,
                member_root_old, member_root_new,
                admin_root_old,  admin_root_new,
                count_*, salt_oc_*, salt_old, salt_new
      public:   c_old, epoch_old, c_new,
                occ_old, occ_new,
                admin_threshold_numerator      (6 scalars)
                              │
                              ▼
              ┌─────────────────────────────────┐
              │   TurboPlonk circuit            │
              │   `oligarchy_update_quorum`     │
              │   single-tier — admin depth 5   │
              │   across all member tiers       │
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
  │  ON-CHAIN  SepOligarchyContract                             │
  └─────────────────────────────────────────────────────────────┘

   ┌────────────────────────────┐  ┌──────────────────────────────┐
   │  create_oligarchy_group    │  │  update_commitment           │
   │                            │  │                              │
   │  PI = (commitment, 0, occ, │  │  PI = (c_old, ep_old, c_new, │
   │        member_root,        │  │         occ_old, occ_new,    │
   │        admin_root,         │  │         admin_threshold)     │
   │        salt_initial)       │  │  6 scalars                   │
   │  6 scalars                 │  │                              │
   │                            │  │  • NO require_auth           │
   │  • caller.require_auth     │  │    (K-of-N proof IS the auth)│
   │  • member_tier ≤ 2         │  │  • c_old == state.commitment │
   │  • threshold ∈ [1, 100]    │  │  • ep_old == BE(state.epoch) │
   │    (CIRCUIT enforces       │  │  • canonical Fr(c_new)       │
   │     ≤ K_MAX = 2 in 2-bit   │  │  • canonical Fr(occ_new)     │
   │     range gate)            │  │  • occ_old == state.occ      │
   │  • canonical Fr(comm), occ │  │  • threshold == BE(          │
   │  • PI[0..3] match wire args│  │      state.threshold)        │
   │    PI[3..6] (root/admin/   │  │    ↑ contract-supplied; the  │
   │    salt) bound by proof    │  │      caller can't lie about  │
   │    but NOT stored on-chain │  │      which threshold the     │
   │  • !group_exists           │  │      proof binds             │
   │  • count < 10 000          │  │  • state.active              │
   │  • SHA256(π) ∉ UsedProof   │  │  • SHA256(π) ∉ UsedProof     │
   │                            │  │                              │
   │  verify(π, VK_CREATE, PI)  │  │  verify(π, VK_UPDATE, PI)    │
   │   ↑ verbose-binding create │  │   ↑ K-of-N quorum + count    │
   │     circuit; admin_root    │  │     delta + admin-tree       │
   │     locked into c at       │  │     Merkle membership        │
   │     creation               │  │                              │
   │                            │  │  archive old → History (≤64) │
   │  record SHA256(π)          │  │  store new entry             │
   │  store CommitmentEntry     │  │    epoch    += 1             │
   │    epoch       = 0         │  │    commitment    = c_new     │
   │    active      = true      │  │    occupancy     = occ_new   │
   │    occupancy   = arg       │  │    threshold preserved       │
   │    threshold   = arg       │  │  record SHA256(π); bump TTLs │
   │  bump TTLs                 │  └────────────┬─────────────────┘
   └────────────┬───────────────┘               │
                │                               ▼
                ▼                       CommitmentUpdated
          GroupCreated

   ┌──────────────────────────────────────────────────────────────┐
   │  verify_membership  (read-only)                              │
   │                                                              │
   │  PI = (commitment, epoch);  matches stored state;            │
   │  verify(π, OLIGARCHY_MEMBERSHIP_VK[tier], PI);               │
   │   ↑ oligarchy-specific membership VK (per-tier d=5/d=8/d=11),│
   │     uses the matching 3-level chain with `Poseidon(occ,      │
   │     admin_root)` as the third hash — created via PR #214 to  │
   │     close the commitment-relation gap with create / update.  │
   │  does NOT consume nullifier.                                 │
   │                                                              │
   │  Returns Ok(true) on accept, Ok(false) on InvalidProof.      │
   └──────────────────────────────────────────────────────────────┘
```

```
              TWO TREES — member tree (per-tier) + admin tree (fixed)
              ═══════════════════════════════════════════════════════

  member tree                                admin tree
  ───────────                                ──────────
  per-tier depth                             FIXED depth 5
  d ∈ {5, 8, 11}                             32 admin slots
  capacity 32 / 256 / 2048                   (per design §4.6 —
  members                                     admin tier always Small,
                                              regardless of member tier)


  At UPDATE time:
    • K_MAX = 2 admin signers each Merkle-open to admin_root_old.
    • member tree only enters the circuit through count-delta on
      `member_count_X` — the count is bound to occupancy_commitment_X
      via Poseidon, the on-chain stored value is the occupancy
      commitment, not the count or the member root itself.
    • member_root_old / member_root_new are private witnesses; the
      circuit binds them into c_old / c_new via the commitment chain
      but does NOT enforce the new tree differs from the old by
      exactly one leaf at a specific position. Tree-level delta is
      future work (carries over from PR #205's documentation).

  At CREATE time:
    • member_root, admin_root, salt_initial all enter as PUBLIC
      INPUTS — exposed via the wire PI vector but not stored
      on-chain. The proof binds them into the commitment, so future
      update / verify_membership calls can rely on c being computed
      under those specific roots without re-stating them.


       SEP-OLIGARCHY ADMIN TREE  (depth 5, signer at index i = 0)
       ═══════════════════════════════════════════════════════════

  K admin signer slots at update time. The active flags must form
  a strict prefix:  (active₀, active₁) ∈ { (0,0), (1,0), (1,1) },
  never (0,1).


       slot 0                                 slot 1
       ───────                                ───────
       sk₀                                    sk₁
       merkle_path_0[]  (length 5)            merkle_path_1[]  (length 5)
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
                  │ (depth = 5)                       │ (depth = 5)
                  ▼                                   ▼
              R₀ (computed)                       R₁ (computed)


     active-conditional gate per slot:
       active_i · (R_i − admin_root_old)  ==  0
     (R_i must equal admin_root_old when slot is active; free
      witness when inactive — so an inactive slot may carry any
      Merkle opening against any other root without breaking the
      gate)


     anti-double-count, for every pair (j, i) with i > j:
       active_j · active_i · is_equal(leaf_idx_j, leaf_idx_i)  ==  0
     (relies on admin-tree uniqueness — distinctness is on
      `leaf_idx`, not `Poseidon(sk)`. The off-circuit admin tree
      builder must dedupe secret keys.)


     K = Σ active_i           K ≤ K_MAX = 2
     K ≥ admin_threshold       threshold ∈ [0, 3]   slack ∈ [0, 3]
       encoded as K = threshold + slack
       both range-checked into 2 bits


  ┌─────────────────────────────────────────────────────────────┐
  │ TIER MAPPING                                                 │
  └─────────────────────────────────────────────────────────────┘

   member tier     d_member   capacity     admin tier   d_admin
   ───────────     ────────   ────────     ──────────   ───────
   tier 0 Small      5            32       Small (fixed)   5
   tier 1 Medium     8           256       Small (fixed)   5
   tier 2 Large     11          2048       Small (fixed)   5

   The update circuit's gate count is **independent of member tier**
   because it doesn't open Merkle paths against the member tree —
   `VK_UPDATE` is a single VK shared across all 3 oligarchy
   member tiers (unlike sep-democracy where the admin signers open
   against the *member* tree and the VK is per-tier).
```

## Notes

- **`commitment` is a 3-level Poseidon at every entrypoint**:
  `c_X = Poseidon(Poseidon(Poseidon(root_X, epoch_X), salt_X),
                  Poseidon(occ_X, admin_root_X))`.
  All three of create, update, and verify_membership use the same
  chain shape — closes the lineage gap that bricked oligarchy from
  PR #200's simplified port through PR #207's quorum baker landing,
  finally reconciled by PR #214's oligarchy-specific membership VK.
- **`admin_root` is a private witness post-create.** It enters as a
  public input only at `create_oligarchy_group` time (PI[4]); from
  then on it lives in `update_commitment` and `verify_membership`
  proofs as a witness reconstructed off-chain from the group's known
  admin set. Per design v0.1.4 §3.5 this is the "hidden admin tree
  root" property — chain observers cannot read the admin tree
  membership directly.
- **`update_commitment` carries no `require_auth`.** Authorization
  is the K-of-N admin quorum proof itself. Replay protection via the
  global `UsedProof(SHA256(π))` nullifier.
- **`verify_membership` does not burn the nullifier.** Read-only by
  design — same proof bytes can be re-presented for offline
  attestation by a verifier who doesn't trust the chain RPC.
- **Threshold is absolute, not percentage** (issue #15). The
  contract validates `admin_threshold_numerator ∈ [1, K_MAX = 2]`,
  matching the deployed quorum circuit's 2-bit slack/threshold range
  gates. Earlier drafts of this README described the threshold as a
  percentage in `[1, 100]`, but the v0.1.4 update circuit ships the
  absolute-threshold gate, not the multiplicative `100·K ≥
  threshold·N` percentage gate that interpretation would require.
  Realistic percentages (50/67/75/100) would create groups that
  brick on the first `update_commitment`; the tightened validation
  closes that footgun. Promoting to a true percentage-quorum circuit
  is follow-up work (would require widened range gates + a
  multiplicative constraint, plus a VK rebake).
- **Two-tree architecture**:
   - **Member tree** is per-tier (depth 5/8/11). The contract stores
     a salted occupancy commitment over the member counts; the actual
     tree never appears on-chain.
   - **Admin tree** is fixed at depth 5 across all member tiers per
     design §4.6 — admins are deliberately small. Keeps the update
     circuit's gate count independent of member-tier, so a single
     `VK_UPDATE` covers all 3 oligarchy member tiers (16,384 gates
     padded to 2^14).
- **Tree-level single-leaf delta is NOT enforced.** Only the count
  delta is. `member_root_new` is bound to `c_new` via the commitment
  chain but the circuit doesn't constrain how the new tree relates
  to the old beyond `|count_new − count_old| ≤ 1`. Documented in
  `oligarchy.rs`'s module header; future work.
- **Stale module docstring**: `lib.rs:19-25` still claims "the PLONK
  ports preserve PI shapes but reduce in-circuit semantics to
  commitment binding" with K-of-N + delta + admin-tree membership
  flagged as follow-up. That's no longer true post-PR #205 / #207 /
  #214 — all three are enforced today (member-tier 0/1/2 for the
  update circuit; per-tier oligarchy-membership at d=5/d=8/d=11).
  Worth updating the docstring in a small follow-up.
