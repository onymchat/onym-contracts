//! SHA-256 binary Merkle trees with caps.
//!
//! - **Leaf**: `SHA256(0x00 ‖ leaf_bytes)`. A leaf holds a whole
//!   folding coset (or a group of trace rows), so one opening serves
//!   every value the verifier needs at that layer.
//! - **Node**: `SHA256(0x01 ‖ left ‖ right)`. The tags keep leaves and
//!   nodes in separate domains.
//! - **Cap**: the commitment is the `2^cap_height` nodes at that
//!   level instead of one root. Paths stop `cap_height` levels early,
//!   which saves `cap_height` digests per opening at the price of
//!   `2^cap_height` digests per tree, sent once.

use crate::hash::{Digest, Hasher};

pub const LEAF_TAG: u8 = 0;
pub const NODE_TAG: u8 = 1;

pub fn leaf_hash<H: Hasher>(h: &H, data: &[u8]) -> Digest {
    h.hash_parts(&[&[LEAF_TAG], data])
}

pub fn node_hash<H: Hasher>(h: &H, left: &Digest, right: &Digest) -> Digest {
    h.hash_parts(&[&[NODE_TAG], left, right])
}

/// `siblings` are leaf-level first. `cap` is the committed cap; the
/// index remaining after walking the path selects the cap node.
pub fn verify_path<H: Hasher>(
    h: &H,
    leaf_data: &[u8],
    mut index: usize,
    siblings: &[Digest],
    cap: &[Digest],
) -> bool {
    let mut acc = leaf_hash(h, leaf_data);
    for sib in siblings {
        acc = if index & 1 == 0 { node_hash(h, &acc, sib) } else { node_hash(h, sib, &acc) };
        index >>= 1;
    }
    index < cap.len() && cap[index] == acc
}
