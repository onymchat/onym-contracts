# sep-tyranny

Per-type **single-admin governance** group on Soroban — only the admin can
advance the commitment. The admin's identity is committed at creation as
`admin_pubkey_commitment = Poseidon(Poseidon(admin_secret_key), group_id_fr)`
and bound to every subsequent update; per-group `group_id_fr` salt closes
cross-group linkability across an admin's groups.

```
                  SEP-TYRANNY  —  single-admin  →  π flow
                  ════════════════════════════════════════

  ┌─────────────────────────────────────────────────────────────┐
  │  OFF-CHAIN PROVER  (pure Rust / arkworks; no host fns)      │
  └─────────────────────────────────────────────────────────────┘

      Admin knows:  admin_secret_key
                      │
                  Poseidon
                      │
                      ▼
                    leaf            ← admin's identity in the
                      │                 member tree (= admin_pubkey)
                      │
       ┌──────────────┴──────────────────┐
       │  placed at index i in a         │
       │  Merkle tree of depth d         │
       │  (d = 5 / 8 / 11 by tier)       │
       │  — admin IS a member            │
       └──────────────┬──────────────────┘
                      │                  │
        Poseidon-up the path             │  also fed forward
        with siblings σ₀…σ_{d-1}         │  for admin binding
                      │                  │
                      ▼                  ▼
                    ROOT              ┌──────────────────────────┐
                      │               │  group_id_fr =           │
                      │               │   canonical Fr(group_id) │
                      │               │   — contract-supplied at │
                      │               │   call time, not on wire │
                      │               └────┬─────────────────────┘
                      │                    │
                      │           Poseidon(leaf, group_id_fr)
                      │                    │
                      │                    ▼
                      │           admin_pubkey_commitment
                      │                    │
                      │                    │  binds admin to THIS
                      │                    │  specific group
                      │                    │  (different group →
                      │                    │   different commitment
                      │                    │   for the same admin)
                      │
       Poseidon(Poseidon(ROOT, epoch), salt)
                      │            ← 2-level chain, identical to
                      ▼              sep-anarchy's membership
                  COMMITMENT           shape — verify_membership
                                       reuses anarchy's per-tier VKs
                      │
                      │     witness:  admin_secret_key, leaf_idx,
                      │               σ₀…σ_{d-1}, ROOT, salt
                      │     public:   commitment, epoch,
                      │               admin_pubkey_commitment,
                      │               group_id_fr   (4 / 5 PIs —
                      │                              create / update)
                      ▼
        ┌──────────────────────────────────┐
        │   TurboPlonk circuit             │
        │   `tyranny_create`  OR           │
        │   `tyranny_update`               │
        │   per-tier (d=5/d=8/d=11)        │
        │   BLS12-381 + EF KZG SRS         │
        └──────────────┬───────────────────┘
                       │
                       ▼
                π  (1601 bytes)
                       │
  ─────────────────────┼─────────────────────  wire boundary
                       │
                       ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  ON-CHAIN  SepTyrannyContract                               │
  └─────────────────────────────────────────────────────────────┘

   ┌──────────────────────────┐    ┌──────────────────────────────┐
   │   create_group           │    │   update_commitment          │
   │                          │    │                              │
   │   PI = (commitment, 0,   │    │   PI = (c_old, ep_old, c_new,│
   │        admin_pubkey_     │    │         admin_pubkey_        │
   │        commitment,       │    │         commitment,          │
   │        group_id_fr)      │    │         group_id_fr)         │
   │   4 scalars              │    │   5 scalars                  │
   │                          │    │                              │
   │   • caller.require_auth  │    │   • NO require_auth          │
   │   • tier ≤ 2             │    │     (admin proof IS the auth)│
   │   • canonical Fr(comm)   │    │   • c_old == state.commitment│
   │   • canonical Fr(admin   │    │   • ep_old == BE(state.epoch)│
   │       pubkey commitment) │    │   • canonical Fr(c_new)      │
   │   • PI[0] == comm arg    │    │   • admin_pubkey_commitment  │
   │   • PI[1] == BE(0)       │    │     PI[3] == storage value   │
   │   • PI[2] == admin       │    │     ↑ contract-supplied; the │
   │       pubkey commitment  │    │       caller can't switch to │
   │       arg                │    │       a different admin      │
   │   • PI[3] == group_id_fr │    │   • PI[4] == group_id_fr     │
   │     ↑ contract-derived   │    │     (per-group binding —     │
   │       from group_id      │    │      contract-derived)       │
   │   • !group_exists        │    │   • SHA256(π) ∉ UsedProof    │
   │   • count < 10 000       │    │                              │
   │   • SHA256(π) ∉ UsedProof│    │   verify(π,                  │
   │                          │    │     UPDATE_VK[tier], PI)     │
   │   verify(π,              │    │                              │
   │     CREATE_VK[tier], PI) │    │   archive old → History (≤64)│
   │                          │    │   store new entry            │
   │   record SHA256(π)       │    │     epoch     += 1           │
   │   store CommitmentEntry  │    │     commitment = c_new       │
   │     epoch = 0            │    │   record SHA256(π); bump TTLs│
   │     tier  = arg          │    └────────────┬─────────────────┘
   │   store AdminCommitment( │                 │
   │     group_id) ← separate │                 ▼
   │     persistent DataKey   │           CommitmentUpdated
   │   bump TTLs              │
   └────────────┬─────────────┘
                │
                ▼
          GroupCreated

   ┌──────────────────────────────────────────────────────────────┐
   │   verify_membership  (read-only)                             │
   │                                                              │
   │   PI = (commitment, epoch);  matches stored state;           │
   │   verify(π, MEMBERSHIP_VK[tier], PI);                        │
   │     ↑ shared with sep-anarchy — the 2-level chain            │
   │       Poseidon(Poseidon(root, epoch), salt) matches          │
   │       what tyranny stores at create / update.                │
   │   does NOT consume nullifier (no SHA256 record).             │
   │                                                              │
   │   Returns Ok(true) on accept, Ok(false) on InvalidProof.     │
   └──────────────────────────────────────────────────────────────┘
```

```
              CIRCUIT CONSTRAINTS  —  what the proof actually proves
              ═══════════════════════════════════════════════════════

  Create (4 public inputs):

   private witness:                  public input:
     admin_secret_key                  commitment
     salt                              epoch  (== 0 at create)
     ROOT  (member tree root)          admin_pubkey_commitment
     merkle_path[d]                    group_id_fr
     leaf_index_bits[d]

   step 1:  leaf := Poseidon(admin_secret_key)
                  ↑ admin's leaf in the member tree
   step 2:  assert Poseidon(leaf, group_id_fr) == admin_pubkey_commitment
                  ↑ admin binding (cross-group salting via group_id_fr)
   step 3:  assert MerkleOpen(leaf, path, idx_bits, d) == ROOT
                  ↑ admin is a member of the tree
   step 4:  assert Poseidon(Poseidon(ROOT, 0), salt) == commitment
                  ↑ standard 2-level chain — same shape anarchy /
                  sep-democracy / sep-oneonone all use


  Update (5 public inputs):

   private witness:                  public input:
     admin_secret_key                  c_old
     salt_old, salt_new                epoch_old
     ROOT_old, ROOT_new                c_new
     merkle_path_old[d]                admin_pubkey_commitment
     leaf_index_old_bits[d]            group_id_fr

   steps 1+2+3:  re-prove admin against ROOT_old
                  (Merkle open against the *old* tree only — the
                  admin must have been a member at the previous
                  state; the new tree's membership is NOT
                  constrained, only its commitment binding)
   step 4:  assert Poseidon(Poseidon(ROOT_old, epoch_old), salt_old) == c_old
   step 5:  epoch_new := epoch_old + 1     ← in-circuit constant
   step 6:  assert Poseidon(Poseidon(ROOT_new, epoch_new), salt_new) == c_new

   The admin must continuously re-prove identity at every update.
   New-tree membership is binding-only (consistent with the standard
   `update` circuit) — the admin can rotate ROOT freely; the
   constraint is just that they're still the same admin.


  ┌─────────────────────────────────────────────────────────────┐
  │ TIER MAPPING                                                │
  └─────────────────────────────────────────────────────────────┘

   tier 0 (Small)   d = 5    capacity 2⁵  =   32    create + update VKs
   tier 1 (Medium)  d = 8    capacity 2⁸  =  256    create + update VKs
   tier 2 (Large)   d = 11   capacity 2¹¹ = 2048    create + update VKs

   `MEMBERSHIP_VK[tier]` is **shared with sep-anarchy** — the 2-PI
   `(commitment, epoch)` shape and the 2-level chain match.
   `CREATE_VK[tier]` and `UPDATE_VK[tier]` are tyranny-specific
   (encode the admin binding constraint).
```

## Notes

- **`commitment` is the standard 2-level chain** —
  `Poseidon(Poseidon(member_root, epoch), salt)`, identical to
  sep-anarchy / sep-oneonone / sep-democracy's create chain. The
  commitment shape is consistent across all three tyranny entrypoints
  AND with the shared anarchy membership VK; no lineage mismatch.
- **`update_commitment` carries no `require_auth`.** Authorization
  is the admin proof itself — the prover demonstrates knowledge of
  the secret key behind `admin_pubkey_commitment` (which the
  contract reads from per-group storage and pins into PI[3]). Replay
  protection via the global `UsedProof(SHA256(π))` nullifier.
- **Cross-group unlinkability via `group_id_fr`.** The same admin
  running multiple tyranny groups produces a *different*
  `admin_pubkey_commitment` in each, because the admin binding is
  `Poseidon(Poseidon(admin_secret_key), group_id_fr)`. A chain
  observer reading raw PI[2/3] values across groups can't tell
  they're the same admin without knowing the secret key (Poseidon
  collision resistance).
- **Admin commitment lives in a separate persistent storage key.**
  `DataKey::AdminCommitment(group_id) → BytesN<32>` — independent of
  `DataKey::Group(group_id)` so the admin binding survives the
  archival flow that rolls `CommitmentEntry` history.
- **No quorum, no threshold.** Tyranny is single-admin by design —
  the K-of-N machinery (slack-bit decomposition, prefix gates,
  anti-double-count) that sep-democracy / sep-oligarchy carry is
  absent. No threshold range mismatch caveat applies.
- **Admin must continuously re-prove at every update.** The update
  circuit re-runs the create circuit's admin-binding constraints
  against `ROOT_old` (steps 1+2+3) — knowledge of the secret key is
  required for *every* update tx, not just at create. This means
  losing the admin secret key permanently freezes the group, since
  no further updates can be produced. There's no admin-rotation
  entrypoint; the design treats the admin's secret key as a
  long-lived per-group artifact.
- **New-tree membership is NOT constrained.** Only `c_new`'s
  binding to `(ROOT_new, epoch_new, salt_new)` is enforced; the
  admin can rotate the member tree freely between epochs, including
  to a tree that doesn't contain their own leaf. The binding-only
  design matches the standard `update` circuit's behaviour.
- **`verify_membership` reuses sep-anarchy's per-tier VKs.** The
  commitment shape is identical, so the same baked `vk-d{N}.bin`
  files serve both contracts.
