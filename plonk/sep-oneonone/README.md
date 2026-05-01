# sep-oneonone

Per-type **immutable two-party** group on Soroban — exactly 2 founding
members, no admin, no quorum, no `update_commitment`, no `deactivate_group`.
A 1v1 group is a single state set at creation and never advanced.

```
                  SEP-ONEONONE  —  (sk₀, sk₁) → π flow
                  ════════════════════════════════════

  ┌─────────────────────────────────────────────────────────────┐
  │  OFF-CHAIN PROVER  (pure Rust / arkworks; no host fns)      │
  └─────────────────────────────────────────────────────────────┘

      Member 0 knows: sk₀                Member 1 knows: sk₁
                │                                │
            Poseidon                         Poseidon
                │                                │
                ▼                                ▼
              leaf₀                            leaf₁
              (private)                       (private)
                │                                │
                └────────────────┬───────────────┘
                                 │
            ┌────────────────────┴────────────────────┐
            │  placed at positions 0 and 1 of a       │
            │  depth-5 Merkle tree;                   │
            │  positions 2..32 are constant zero      │
            │  (the circuit has no slot for more      │
            │  leaves — "exactly 2" is structural)    │
            └────────────────────┬────────────────────┘
                                 │
                  Poseidon-up the active left spine
                  (right subtrees fold to inlined
                   constants Z₀..Z₃ at synth-time)
                                 │
                                 ▼
                               ROOT             ← member tree root
                                 │                 (private witness)
                                 │
                Poseidon(Poseidon(ROOT, 0), salt)
                                 │                 ← salt is a per-group
                                 ▼                   private witness
                            COMMITMENT          ← THIS is what's stored
                                 │                 PI[0] for both
                                 │                 entrypoints below
                                 │
                                 │   witness:  sk₀, sk₁, salt
                                 │   public:   COMMITMENT, epoch
                                 ▼
                ┌─────────────────────────────────┐
                │   TurboPlonk circuit            │
                │   (Create  OR  Membership)      │
                │   BLS12-381 + EF KZG SRS        │
                │   Single tier (depth = 5)       │
                └──────────────┬──────────────────┘
                               │
                               ▼
                        π  (1601 bytes)
                               │
  ─────────────────────────────┼─────────────────────  wire boundary
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  ON-CHAIN  SepOneOnOneContract                              │
  └─────────────────────────────────────────────────────────────┘

   ┌──────────────────────────┐    ┌──────────────────────────────┐
   │   create_group           │    │   verify_membership          │
   │                          │    │   (read-only)                │
   │   PI = (COMMITMENT, 0)   │    │                              │
   │   2 scalars              │    │   PI = (commitment, epoch)   │
   │                          │    │   2 scalars                  │
   │   • caller.require_auth  │    │                              │
   │   • canonical Fr(comm)   │    │   • PI matches stored state  │
   │   • PI[0] == comm arg    │    │   • verify(π, MEMBERSHIP_VK, │
   │   • PI[1] == BE(0)       │    │             PI)              │
   │   • !group_exists        │    │     ↑ same VK as sep-anarchy │
   │   • count < 10 000       │    │       depth-5 — 1v1 commitment│
   │   • SHA256(π) ∉ UsedProof│    │       shape matches           │
   │                          │    │                              │
   │   verify(π, CREATE_VK,   │    │   Returns Ok(true) on accept;│
   │          PI)             │    │   Ok(false) on InvalidProof. │
   │                          │    │   Does NOT consume nullifier.│
   │   ↑ 1v1-specific VK —    │    │                              │
   │     enforces "exactly 2  │    └──────────────────────────────┘
   │     non-zero leaves" via │
   │     the witness shape    │
   │     (no slot for more)   │      (No update_commitment —
   │                          │       1v1 groups are immutable.
   │   record SHA256(π)       │       No deactivate either.)
   │   store CommitmentEntry  │
   │     commitment           │
   │     epoch = 0            │
   │     timestamp            │
   │   bump TTL               │
   └────────────┬─────────────┘
                │
                ▼
          GroupCreated
```

```
       SEP-ONEONONE MERKLE TREE — depth 5, 2 of 32 leaves populated
       ═════════════════════════════════════════════════════════════

  Active spine on the LEFT (positions 0/1 of the tree).
  Right subtree at every level folds to an inlined zero-constant
  Z_k computed at synthesis time (saves ~32 000 in-circuit gates):

      Z₀ = Poseidon(0, 0)            ← root of a 1-level zero subtree
      Z₁ = Poseidon(Z₀, Z₀)          ← root of a 2-level zero subtree
      Z₂ = Poseidon(Z₁, Z₁)
      Z₃ = Poseidon(Z₂, Z₂)


  level 5  (root)                            ROOT
                                              │       ← witness; combined
                                            ╱─┴─╲       with epoch + salt
                                          ╱       ╲     to form COMMITMENT
                                        ╱           ╲
  level 4                          spine_4            Z₃
                                (in-circuit)       (synth-time
                                                    constant)
                                    │
                                  ╱─┴─╲
                                ╱       ╲
  level 3                  spine_3        Z₂
                          (in-circuit)  (constant)
                              │
                            ╱─┴─╲
                          ╱       ╲
  level 2             spine_2       Z₁
                    (in-circuit) (constant)
                        │
                      ╱─┴─╲
                    ╱       ╲
  level 1       spine_1       Z₀
              (in-circuit) (constant)
                  │
                ╱─┴─╲
              ╱       ╲
  level 0    leaf₀   leaf₁     0   0   0  …  0   (30 constant-pinned
              ★       ★          ↑ positions 2..31         zero leaves)
        Poseidon Poseidon          (no witness slot ⇒
         (sk₀)   (sk₁)             prover cannot place
                                   any third leaf)


  ┌─────────────────────────────────────────────────────────────┐
  │ CIRCUIT COMPUTATION  (Create)                                │
  └─────────────────────────────────────────────────────────────┘

   private witness:                          public input:
     sk₀, sk₁                                  commitment
     salt                                      epoch  (= 0 at create)

   step 0:  leaf₀     := Poseidon(sk₀)
   step 1:  leaf₁     := Poseidon(sk₁)
   step 2:  spine_1   := Poseidon(leaf₀,   leaf₁)
   step 3:  spine_2   := Poseidon(spine_1, Z₀)
   step 4:  spine_3   := Poseidon(spine_2, Z₁)
   step 5:  spine_4   := Poseidon(spine_3, Z₂)
   step 6:  ROOT      := Poseidon(spine_4, Z₃)
   step 7:  assert Poseidon(Poseidon(ROOT, epoch), salt) == commitment

   9 in-circuit Poseidon ops total (2 leaf + 5 spine + 2 commitment).


  ┌─────────────────────────────────────────────────────────────┐
  │ CIRCUIT COMPUTATION  (Membership — same shape as anarchy)    │
  └─────────────────────────────────────────────────────────────┘

   The Membership VK is the **shared sep-anarchy depth-5 VK**, not a
   1v1-specific one. After create, either member can prove membership
   by opening their leaf along the active spine — same Merkle gadget
   as sep-anarchy, just walking up positions 0 or 1 of a tree whose
   later positions happen to be zero.

   private witness:                          public input:
     sk_i  (one of sk₀, sk₁)                   commitment
     index_bits = (i==0 ? (0,0,0,0,0)          epoch
                        : (1,0,0,0,0))
     siblings   = (σ₀=leaf_{1-i}, Z₀, Z₁, Z₂, Z₃)
     ROOT, salt

   The same spine Z₀..Z₃ that the create circuit folds in as
   constants are the legitimate sibling values for ANY membership
   opening on a 1v1 tree — no special-casing in the membership VK.
```

## Notes

- **VK split, single tier.** Two distinct VKs are baked in:
  `MEMBERSHIP_VK` = `vk-d5.bin` (shared with `sep-anarchy`) for
  `verify_membership`, and `CREATE_VK` = `oneonone-create-vk.bin`
  (1v1-specific) for `create_group`. The create VK enforces the
  "exactly 2 leaves" structural invariant; the membership VK doesn't
  need to know about that constraint because the commitment shape is
  identical regardless of how many leaves the underlying tree had.
- **Tier is hardcoded.** Depth = 5, capacity 32 (of which 30 stay
  zero forever). No `member_tier` argument — the only meaningful 1v1
  case is "two parties", and the cap-of-32 is generous slack.
- **Immutable.** No `update_commitment` entrypoint. Once a 1v1 group
  is created, the on-chain `commitment` is frozen. Replay protection
  via the global `UsedProof(SHA256(π))` nullifier still applies — the
  same create proof bytes can never start two groups.
- **Synthesis-time zero-folding.** The naive depth-5 tree
  reconstruction is ~32k gates — exactly the n=32,768 SRS ceiling, and
  jf-plonk's preprocess needs *strictly more* powers than gates. The
  optimization at `oneonone_create.rs:73-99` precomputes the
  `Z_0..Z_{depth-1}` zero-subtree constants at synthesis time and
  inlines them, leaving only `DEPTH` Poseidon ops in the active spine.
- **Membership-VK reuse.** A 1v1 group's commitment is byte-identical
  to what the standard `MembershipCircuit` would produce against the
  same `(root, epoch, salt)` triple. So even though `create_group`
  uses a structurally-stricter circuit, the resulting commitment
  verifies against the shared depth-5 membership VK — no separate
  "1v1 membership" path required.
