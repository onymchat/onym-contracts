//! Hash abstraction shared by the on-chain verifier and the prover.
//!
//! The verifier only ever needs "SHA-256 of these byte slices,
//! concatenated". On-chain that is `env.crypto().sha256(...)`;
//! off-chain it is the `sha2` crate. Both see identical input bytes,
//! so commitments and Fiat–Shamir challenges agree.

pub type Digest = [u8; 32];

pub trait Hasher {
    /// SHA-256 of `parts` concatenated in order.
    fn hash_parts(&self, parts: &[&[u8]]) -> Digest;
}

/// Software SHA-256 for the prover and native tests.
#[cfg(feature = "prover")]
pub struct Sha2Hasher;

#[cfg(feature = "prover")]
impl Hasher for Sha2Hasher {
    fn hash_parts(&self, parts: &[&[u8]]) -> Digest {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }
}
