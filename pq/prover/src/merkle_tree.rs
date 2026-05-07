//! Binary Merkle tree *builder* — prover-side counterpart of
//! `fri_verifier::merkle::verify_path`.
//!
//! ## Layout
//!
//! Same as the verifier:
//! - Leaves are single BN254 Fr elements (32 bytes BE).
//! - Inner nodes are `Poseidon2-t3([left, right, 0])[0]`.
//!
//! Stored layer-major: `levels[0]` = leaves, `levels[depth]` = `[root]`.

use fri_verifier::field::Fr;
use fri_verifier::host_poseidon2::Poseidon2Ctx;
use fri_verifier::merkle::{compress, leaf_digest_for as _verifier_leaf, Digest};
use soroban_sdk::Env;

pub struct MerkleTree {
    pub levels: alloc::vec::Vec<alloc::vec::Vec<Digest>>,
}

impl MerkleTree {
    /// Build a binary Merkle tree from leaf digests. `leaves.len()`
    /// must be a power of two ≥ 2.
    pub fn build(env: &Env, ctx: &Poseidon2Ctx, leaves: alloc::vec::Vec<Digest>) -> Self {
        let n = leaves.len();
        assert!(n >= 2, "tree needs ≥ 2 leaves");
        assert!(n.is_power_of_two(), "leaf count must be power of 2");
        let mut levels: alloc::vec::Vec<alloc::vec::Vec<Digest>> =
            alloc::vec::Vec::with_capacity(64);
        levels.push(leaves);
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next: alloc::vec::Vec<Digest> = alloc::vec::Vec::with_capacity(prev.len() / 2);
            for chunk in prev.chunks(2) {
                next.push(compress(env, ctx, &chunk[0], &chunk[1]));
            }
            levels.push(next);
        }
        MerkleTree { levels }
    }

    pub fn root(&self) -> Digest {
        self.levels.last().unwrap()[0].clone()
    }

    /// Authentication path for `leaf_index`. Returned siblings are
    /// in ascending-level order to match
    /// `fri_verifier::merkle::verify_path`.
    pub fn auth_path(&self, leaf_index: usize) -> alloc::vec::Vec<Digest> {
        let depth = self.levels.len() - 1;
        let mut path = alloc::vec::Vec::with_capacity(depth);
        let mut idx = leaf_index;
        for l in 0..depth {
            let sib_idx = idx ^ 1;
            path.push(self.levels[l][sib_idx].clone());
            idx >>= 1;
        }
        path
    }
}

/// Leaf-digest convention. With BN254 t=3 the leaf hash *is* the
/// value — the tree's first compression layer handles the (sibling,
/// sibling) pair.
pub fn leaf_digest_for(v: Fr) -> Digest {
    _verifier_leaf(v)
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;
    use fri_verifier::field;
    use fri_verifier::merkle::verify_path;

    #[test]
    fn auth_path_roundtrip() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let n = 16usize;
        let leaves: alloc::vec::Vec<Digest> = (0..n)
            .map(|i| leaf_digest_for(field::from_u32(&env, (i as u32) * 17 + 1)))
            .collect();
        let tree = MerkleTree::build(&env, &ctx, leaves.clone());
        let root = tree.root();
        for i in 0..n {
            let path = tree.auth_path(i);
            assert_eq!(
                verify_path(&env, &ctx, &leaves[i], i as u64, &path, &root),
                Ok(()),
                "leaf {i} path didn't verify",
            );
        }
    }

    #[test]
    fn tampered_leaf_rejects() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let leaves: alloc::vec::Vec<Digest> = (0..8)
            .map(|i| leaf_digest_for(field::from_u32(&env, i as u32 + 1)))
            .collect();
        let tree = MerkleTree::build(&env, &ctx, leaves.clone());
        let root = tree.root();
        let bad_leaf = leaves[3].clone() + field::one(&env);
        let path = tree.auth_path(3);
        assert!(verify_path(&env, &ctx, &bad_leaf, 3, &path, &root).is_err());
    }
}
