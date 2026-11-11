//! Membership AIR: the PQ analogue of `plonk/prover`'s
//! `MembershipCircuit`.
//!
//! ## Statement
//!
//! Public: `commitment` (8 elements), `epoch` (u64).
//! Private: `sk` (8), `path[d]` (8 each), `index_bits[d]`, `salt` (8).
//!
//! ```text
//!   leaf       = H(sk ‖ 0⁸)                       key ownership
//!   root       = MerkleOpen(leaf, path, bits)       membership (private root)
//!   commitment = H(H(root ‖ epoch limbs ‖ 0⁵) ‖ salt) epoch + salt binding
//! ```
//!
//! `H` = first 8 lanes of Poseidon2-BabyBear-16. That is `d + 3`
//! permutations.
//!
//! ## Layout: one 32-row block per permutation, one row per round
//!
//! Columns (`W = 25`): `s[0..16]` state, `sib[0..8]`, `bit`.
//!
//! ```text
//!   block row  meaning of s           transition r → r+1
//!   ─────────  ────────────────────   ────────────────────────────────
//!   0          raw input              first: M_E then external round 0
//!   1..3       after ext round r      external rounds 1..3
//!   4..16      after ext/int round    internal rounds 0..12
//!   17..20     after int/ext round    external rounds 4..7
//!   21..30     output (held)          copy
//!   31         output (link row)      link into the next block's input
//! ```
//!
//! Selectors and round constants are **periodic columns** (period 32):
//! the verifier evaluates them itself at `z`, so they cost no proof
//! bytes. Link rows carry `sib`/`bit`:
//!
//! - blocks `0..d−1` → next: `next = bit ? (sib ‖ cur) : (cur ‖ sib)`
//! - block `d` → epoch block: `next = cur ‖ epoch limbs ‖ 0⁵`
//! - block `d+1` → salt block: `next = cur ‖ sib` (`sib` = salt)
//!
//! Boundary: block 0 input lanes 8..16 are zero; block `d+2` output
//! lanes 0..8 equal `commitment`. Blocks past `d+2` are padding up to a
//! power of two; they run valid permutations but are never linked.
//!
//! ## Constraint groups (and their divisors)
//!
//! | group  | count | vanishes on                | divisor              |
//! |--------|-------|----------------------------|----------------------|
//! | round  | 16    | every row                  | `xⁿ − 1`             |
//! | merkle | 17    | link rows of blocks 0..d−1 | `Π (x − g^(32b+31))` |
//! | epoch  | 16    | link row of block d        | `x − g^(32d+31)`     |
//! | salt   | 16    | link row of block d+1      | `x − g^(32(d+1)+31)` |
//! | leaf   | 8     | row 0                      | `x − 1`              |
//! | commit | 8     | row 32(d+2)+31             | `x − g^(32(d+2)+31)` |

use crate::field::{Algebra, F};
use crate::poseidon2::{self, DIGEST, ROUNDS_EXT_HALF, ROUNDS_INT, WIDTH};
use alloc::vec::Vec;

pub const BLOCK: usize = 32;
pub const LOG_BLOCK: u32 = 5;
pub const COL_SIB: usize = WIDTH;
pub const COL_BIT: usize = WIDTH + DIGEST;
pub const NUM_COLS: usize = WIDTH + DIGEST + 1;

/// Periodic columns: 4 selectors, then 16 round-constant lanes.
pub const PER_FIRST: usize = 0;
pub const PER_EXT: usize = 1;
pub const PER_INT: usize = 2;
pub const PER_HOLD: usize = 3;
pub const PER_RC: usize = 4;
pub const NUM_PERIODIC: usize = 4 + WIDTH;

pub const NUM_CONSTRAINTS: usize = 16 + 17 + 16 + 16 + 8 + 8;

/// Epoch as three 22-bit limbs (covers all of u64).
pub fn epoch_limbs(epoch: u64) -> [F; 3] {
    let m = (1u64 << 22) - 1;
    [F::from_u64(epoch & m), F::from_u64((epoch >> 22) & m), F::from_u64(epoch >> 44)]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub depth: usize,
    pub log_blocks: u32,
}

impl Shape {
    pub fn new(depth: usize) -> Shape {
        let blocks = (depth + 3).next_power_of_two();
        Shape { depth, log_blocks: blocks.trailing_zeros() }
    }
    pub fn blocks(&self) -> usize {
        1 << self.log_blocks
    }
    pub fn log_n(&self) -> u32 {
        self.log_blocks + LOG_BLOCK
    }
    pub fn n(&self) -> usize {
        1 << self.log_n()
    }
    pub fn link_row(&self, block: usize) -> usize {
        BLOCK * block + BLOCK - 1
    }
}

pub struct PublicInputs {
    pub commitment: [F; DIGEST],
    pub epoch: u64,
}

impl PublicInputs {
    pub const BYTES: usize = 4 * DIGEST + 8;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        for i in 0..DIGEST {
            out[4 * i..4 * i + 4].copy_from_slice(&self.commitment[i].value().to_le_bytes());
        }
        out[4 * DIGEST..].copy_from_slice(&self.epoch.to_le_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<PublicInputs> {
        if b.len() != Self::BYTES {
            return None;
        }
        let mut commitment = [F::ZERO; DIGEST];
        for i in 0..DIGEST {
            let v = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
            commitment[i] = F::from_canonical(v)?;
        }
        let epoch = u64::from_le_bytes(b[4 * DIGEST..].try_into().unwrap());
        Some(PublicInputs { commitment, epoch })
    }
}

/// Values of the 20 periodic columns at block row `r`.
pub fn periodic_row(r: usize) -> [F; NUM_PERIODIC] {
    let mut v = [F::ZERO; NUM_PERIODIC];
    let rc: Option<[F; WIDTH]> = match r {
        0 => {
            v[PER_FIRST] = F::ONE;
            Some(poseidon2::rc_ext(0))
        }
        1..=3 => {
            v[PER_EXT] = F::ONE;
            Some(poseidon2::rc_ext(r))
        }
        4..=16 => {
            v[PER_INT] = F::ONE;
            let mut lanes = [F::ZERO; WIDTH];
            lanes[0] = poseidon2::rc_int(r - 4);
            Some(lanes)
        }
        17..=20 => {
            v[PER_EXT] = F::ONE;
            Some(poseidon2::rc_ext(r - 17 + ROUNDS_EXT_HALF))
        }
        21..=30 => {
            v[PER_HOLD] = F::ONE;
            None
        }
        _ => None,
    };
    if let Some(rc) = rc {
        v[PER_RC..].copy_from_slice(&rc);
    }
    v
}

const _: () = assert!(2 * ROUNDS_EXT_HALF + ROUNDS_INT == 21);

/// All constraint numerators at one point, in the fixed group order of
/// the module docs. `local`/`next` are the `NUM_COLS` trace values at
/// `x` and `g·x`; `per` the periodic values at `x`.
pub fn eval<A: Algebra>(
    shape: &Shape,
    local: &[A],
    next: &[A],
    per: &[A],
    pi: &PublicInputs,
    out: &mut Vec<A>,
) {
    let _ = shape;
    out.clear();
    let s: [A; WIDTH] = local[..WIDTH].try_into().unwrap();
    let rc: [A; WIDTH] = per[PER_RC..PER_RC + WIDTH].try_into().unwrap();
    let (s_first, s_ext, s_int, s_hold) = (per[PER_FIRST], per[PER_EXT], per[PER_INT], per[PER_HOLD]);
    let active = s_first + s_ext + s_int + s_hold;

    // ---- round: next = selected round function (or copy) ----------
    let mut pre = s;
    poseidon2::external_linear(&mut pre);
    let first = poseidon2::external_round(&pre, &rc);
    let ext = poseidon2::external_round(&s, &rc);
    let int = poseidon2::internal_round(&s, rc[0]);
    for i in 0..WIDTH {
        out.push(active * next[i] - s_first * first[i] - s_ext * ext[i] - s_int * int[i] - s_hold * s[i]);
    }

    // ---- merkle link ------------------------------------------------
    let sib = &local[COL_SIB..COL_SIB + DIGEST];
    let bit = local[COL_BIT];
    for i in 0..DIGEST {
        out.push(next[i] - (s[i] + bit * (sib[i] - s[i])));
    }
    for i in 0..DIGEST {
        out.push(next[DIGEST + i] - (sib[i] + bit * (s[i] - sib[i])));
    }
    out.push(bit * (A::ONE - bit));

    // ---- epoch link -------------------------------------------------
    let limbs = epoch_limbs(pi.epoch);
    for i in 0..DIGEST {
        out.push(next[i] - s[i]);
    }
    for i in 0..3 {
        out.push(next[DIGEST + i] - A::from(limbs[i]));
    }
    for i in DIGEST + 3..WIDTH {
        out.push(next[i]);
    }

    // ---- salt link --------------------------------------------------
    for i in 0..DIGEST {
        out.push(next[i] - s[i]);
    }
    for i in 0..DIGEST {
        out.push(next[DIGEST + i] - sib[i]);
    }

    // ---- leaf boundary: block 0 input lanes 8..16 are zero ----------
    for i in DIGEST..WIDTH {
        out.push(s[i]);
    }

    // ---- commitment boundary ----------------------------------------
    for i in 0..DIGEST {
        out.push(s[i] - A::from(pi.commitment[i]));
    }
    debug_assert_eq!(out.len(), NUM_CONSTRAINTS);
}

/// Group boundaries into the `eval` output, paired with group ids.
pub const GROUPS: [(usize, usize); 6] = [(0, 16), (16, 33), (33, 49), (49, 65), (65, 73), (73, 81)];
pub const G_ROUND: usize = 0;
pub const G_MERKLE: usize = 1;
pub const G_EPOCH: usize = 2;
pub const G_SALT: usize = 3;
pub const G_LEAF: usize = 4;
pub const G_COMMIT: usize = 5;

/// Divisor of each group at `x`, given `xⁿ` and the trace generator `g`.
pub fn divisors<A: Algebra>(shape: &Shape, x: A, x_n: A, g: F) -> [A; 6] {
    let gp = |row: usize| A::from(g.pow(row as u64));
    let mut merkle = A::ONE;
    for b in 0..shape.depth {
        merkle = merkle * (x - gp(shape.link_row(b)));
    }
    [
        x_n - A::ONE,
        merkle,
        x - gp(shape.link_row(shape.depth)),
        x - gp(shape.link_row(shape.depth + 1)),
        x - A::ONE,
        x - gp(shape.link_row(shape.depth + 2)),
    ]
}

/// Witness for one membership proof.
pub struct Witness {
    pub sk: [F; DIGEST],
    pub path: Vec<[F; DIGEST]>,
    pub index: usize,
    pub salt: [F; DIGEST],
    pub epoch: u64,
}

impl Witness {
    pub fn root(&self) -> [F; DIGEST] {
        let mut input = [F::ZERO; WIDTH];
        input[..DIGEST].copy_from_slice(&self.sk);
        let mut cur: [F; DIGEST] = poseidon2::permute(input)[..DIGEST].try_into().unwrap();
        for (lvl, sib) in self.path.iter().enumerate() {
            cur = if (self.index >> lvl) & 1 == 1 {
                poseidon2::compress(sib, &cur)
            } else {
                poseidon2::compress(&cur, sib)
            };
        }
        cur
    }

    pub fn public_inputs(&self) -> PublicInputs {
        let mut input = [F::ZERO; WIDTH];
        input[..DIGEST].copy_from_slice(&self.root());
        input[DIGEST..DIGEST + 3].copy_from_slice(&epoch_limbs(self.epoch));
        let h1: [F; DIGEST] = poseidon2::permute(input)[..DIGEST].try_into().unwrap();
        PublicInputs { commitment: poseidon2::compress(&h1, &self.salt), epoch: self.epoch }
    }

    /// Row-major trace, `n × NUM_COLS`.
    pub fn trace(&self, shape: &Shape) -> Vec<[F; NUM_COLS]> {
        let d = shape.depth;
        assert_eq!(self.path.len(), d);
        let mut rows = alloc::vec![[F::ZERO; NUM_COLS]; shape.n()];
        let mut input = [F::ZERO; WIDTH];
        input[..DIGEST].copy_from_slice(&self.sk);
        for b in 0..shape.blocks() {
            let states = poseidon2::permute_trace(input);
            for r in 0..BLOCK {
                rows[BLOCK * b + r][..WIDTH].copy_from_slice(&states[r.min(21)]);
            }
            let out: [F; DIGEST] = states[21][..DIGEST].try_into().unwrap();
            let link = &mut rows[shape.link_row(b)];
            input = [F::ZERO; WIDTH];
            if b < d {
                let bit = (self.index >> b) & 1 == 1;
                link[COL_SIB..COL_SIB + DIGEST].copy_from_slice(&self.path[b]);
                link[COL_BIT] = if bit { F::ONE } else { F::ZERO };
                let (l, r) = if bit { (self.path[b], out) } else { (out, self.path[b]) };
                input[..DIGEST].copy_from_slice(&l);
                input[DIGEST..].copy_from_slice(&r);
            } else if b == d {
                input[..DIGEST].copy_from_slice(&out);
                input[DIGEST..DIGEST + 3].copy_from_slice(&epoch_limbs(self.epoch));
            } else if b == d + 1 {
                link[COL_SIB..COL_SIB + DIGEST].copy_from_slice(&self.salt);
                input[..DIGEST].copy_from_slice(&out);
                input[DIGEST..].copy_from_slice(&self.salt);
            }
            // b ≥ d+2: next block is padding with a zero input.
        }
        rows
    }
}
