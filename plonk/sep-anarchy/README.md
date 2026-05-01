# sep-anarchy

Per-type **single-signer** membership group on Soroban — no admin, no quorum,
no occupancy hiding. A member proves "I know a secret key behind a leaf in
the group's tree" via a TurboPlonk membership proof; that single proof is
sufficient authorization to *both* read state (`verify_membership`) and to
advance the group epoch (`update_commitment`).

```
                  SEP-ANARCHY  —  sk → π flow
                  ════════════════════════════

  ┌─────────────────────────────────────────────────────────────┐
  │  OFF-CHAIN PROVER  (pure Rust / arkworks; no host fns)      │
  └─────────────────────────────────────────────────────────────┘

      Member knows:  sk
                      │
                  Poseidon
                      │
                      ▼
                    leaf            ← identity commitment
                      │                 (private, NOT on-chain)
                      │
       ┌──────────────┴──────────────┐
       │  placed at index i in a     │
       │  Merkle tree of depth d     │
       │  (d = 5 / 8 / 11 by tier)   │
       └──────────────┬──────────────┘
                      │
        Poseidon-up the path with siblings σ₀ … σ_{d-1}
                      │
                      ▼
                    ROOT            ← member tree root
                      │                 (private witness)
                      │
       Poseidon(Poseidon(ROOT, epoch), salt)
                      │                 ← salt is a per-state private witness
                      ▼                   shared off-chain by group members
                  COMMITMENT        ← THIS is what's stored on-chain
                      │                 PI[0] for every entrypoint below
                      │
                      │     witness:  sk, i, σ₀…σ_{d-1}, ROOT, salt
                      │     public:   COMMITMENT, epoch
                      ▼
        ┌─────────────────────────────────┐
        │   TurboPlonk circuit            │
        │   (Membership  OR  Update)      │
        │   BLS12-381 + EF KZG SRS        │
        │   VK baked per tier (d5/d8/d11) │
        └──────────────┬──────────────────┘
                       │
                       ▼
                π  (1601 bytes)
                       │
  ─────────────────────┼─────────────────────  wire boundary
                       │
                       ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  ON-CHAIN  SepAnarchyContract                               │
  └─────────────────────────────────────────────────────────────┘

   ┌─────────────────────────┐       ┌──────────────────────────────┐
   │   create_group          │       │   update_commitment          │
   │                         │       │                              │
   │   PI = (COMMITMENT, 0)  │       │   PI = (c_old, ep_old, c_new)│
   │   2 scalars             │       │   3 scalars                  │
   │                         │       │                              │
   │   • caller.require_auth │       │   • NO require_auth          │
   │   • tier ≤ 2            │       │     (proof IS the auth)      │
   │   • canonical Fr(comm)  │       │   • c_old == state.commitment│
   │   • PI[0] == comm arg   │       │   • ep_old == BE(state.epoch)│
   │   • PI[1] == BE(0)      │       │   • canonical Fr(c_new)      │
   │   • !group_exists       │       │   • state.active             │
   │   • tier count < 10 000 │       │   • SHA256(π) ∉ UsedProof    │
   │   • SHA256(π) ∉ UsedProof│      │                              │
   │                         │       │   verify(π, UPDATE_VK_d, PI) │
   │   verify(π, VK_d, PI)   │       │                              │
   │                         │       │   archive old → History (≤64)│
   │   store CommitmentEntry │       │   store new entry            │
   │     epoch        = 0    │       │     epoch        += 1        │
   │     active       = true │       │     commitment   = c_new     │
   │     member_count = arg  │       │     member_count = preserved │
   │     (informational)     │       │                              │
   │   record SHA256(π)      │       │   record SHA256(π)           │
   │   bump TTLs             │       │   bump TTLs                  │
   └────────────┬────────────┘       └────────────┬─────────────────┘
                │                                 │
                ▼                                 ▼
          GroupCreated                     CommitmentUpdated

   ┌──────────────────────────────────────────────────────────────┐
   │   verify_membership  (read-only)                             │
   │                                                              │
   │   PI = (commitment, epoch);  matches stored state;           │
   │   verify(π, VK_d, PI);                                       │
   │   does NOT consume nullifier (no SHA256 record).             │
   │                                                              │
   │   Returns Ok(true) on accept, Ok(false) on InvalidProof —    │
   │   no panic on rejection.                                     │
   └──────────────────────────────────────────────────────────────┘
```

```
              SEP-ANARCHY MERKLE TREE — TIER 0 (depth 5, capacity 32)
              ═══════════════════════════════════════════════════════

  Member at index i = 13  (binary 01101).
  Path bits read leaf→root, LSB first:  1, 0, 1, 1, 0
    bit = 1  → "I'm the right child here";  sibling is on the LEFT
    bit = 0  → "I'm the left child";        sibling is on the RIGHT


  level 5  (root)                            ROOT
                                              │      ← witness; hashed with
                                            ╱─┴─╲      epoch + salt to form
                                          ╱       ╲    on-chain COMMITMENT
                                        ╱           ╲
                                      ╱               ╲
  level 4                       L4                       σ₄
                            (computed,                (witness;
                          left-of-root)              right sibling)
                              │                        bit_4 = 0
                            ╱─┴─╲
                          ╱       ╲
                        ╱           ╲
  level 3            σ₃              L3
                  (witness;        (computed,
                left sibling)     right-of-σ₃)
                  bit_3 = 1           │
                                    ╱─┴─╲
                                  ╱       ╲
  level 2                       L2          σ₂
                            (computed,    (witness;
                          right-of-σ₂)   left sibling)
                              │            bit_2 = 1
                            ╱─┴─╲
                          ╱       ╲
  level 1                σ₁         L1
                      (witness;   (computed,
                    right sibling) left-of-σ₁)
                      bit_1 = 0       │
                                    ╱─┴─╲
                                  ╱       ╲
  level 0                       leaf₁₂      leaf₁₃ = Poseidon(sk)  ★
                                σ₀                       (the prover's leaf)
                              (witness;
                            left sibling)
                              bit_0 = 1


  ┌─────────────────────────────────────────────────────────────┐
  │ CIRCUIT COMPUTATION  (Membership, depth 5)                   │
  └─────────────────────────────────────────────────────────────┘

   private witness:                          public input:
     sk                                        commitment
     index_bits = (1, 0, 1, 1, 0)              epoch
     siblings   = (σ₀, σ₁, σ₂, σ₃, σ₄)
     ROOT, salt

   step 0:  leaf := Poseidon(sk)
   step 1:  L0   := bit_0 == 1 ? Poseidon(σ₀, leaf) : Poseidon(leaf, σ₀)
   step 2:  L1   := bit_1 == 1 ? Poseidon(σ₁, L0  ) : Poseidon(L0,   σ₁ )
   step 3:  L2   := bit_2 == 1 ? Poseidon(σ₂, L1  ) : Poseidon(L1,   σ₂ )
   step 4:  L3   := bit_3 == 1 ? Poseidon(σ₃, L2  ) : Poseidon(L2,   σ₃ )
   step 5:  L4   := bit_4 == 1 ? Poseidon(σ₄, L3  ) : Poseidon(L3,   σ₄ )
   step 6:  assert L4 == ROOT                              (membership)
   step 7:  assert Poseidon(Poseidon(ROOT, epoch), salt) == commitment
                                                           (commitment binding)
```

```
           TIER MAPPING
           ════════════

   tier 0 (Small)   d = 5    capacity 2⁵  =   32    VK_D5  / UPDATE_VK_D5
   tier 1 (Medium)  d = 8    capacity 2⁸  =  256    VK_D8  / UPDATE_VK_D8
   tier 2 (Large)   d = 11   capacity 2¹¹ = 2048    VK_D11 / UPDATE_VK_D11
```

## Notes

- **`commitment` is not the Merkle root.** The on-chain commitment hides
  both the root *and* the per-state salt behind two Poseidon levels. Two
  groups with the same membership at the same epoch but different salts
  produce different on-chain commitments — making cross-group correlation
  by chain observers infeasible without the salt.
- **`update_commitment` doesn't take `caller.require_auth`.** Anyone can
  submit on behalf of the group; the membership proof is the auth.
  Replay protection comes from the global `UsedProof(SHA256(π))`
  nullifier — the same proof bytes can never advance the group twice.
- **`verify_membership` doesn't burn the nullifier.** Read-only by design;
  the same proof bytes can be re-presented indefinitely (e.g. for offline
  attestation by a verifier who doesn't trust the chain RPC).
- **`member_count` is informational.** The contract has no Poseidon host
  to validate it against the tree, so it's accepted at create time as a
  hint for clients and preserved verbatim through updates.
