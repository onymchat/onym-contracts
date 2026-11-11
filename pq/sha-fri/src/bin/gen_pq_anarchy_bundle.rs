//! Chained `create_group` → `update_commitment` proof bundle for the
//! `pq/sep-anarchy` testnet bench.
//!
//! ```text
//!   cargo run --release --features prover --bin gen-pq-anarchy-bundle -- \
//!       --depth 11 --profile johnson --seed 7 --out-dir ./bundle
//! ```
//!
//! One random member at epoch 0 proves membership (create; reused for
//! verify_membership), then the same member proves an update to a random
//! new root/salt at epoch 1, so `update.c_old == create.commitment`.
//!
//! Writes (`public_inputs.json` is the contract's `Vec<BytesN<32>>`:
//! digests as 8 × u32 LE, epochs as 32-byte big-endian):
//! - `create/proof.bin`, `create/public_inputs.json`  `[commitment, be32(0)]`
//! - `update/proof.bin`, `update/public_inputs.json`  `[c_old, be32(0), c_new]`
//! - `commitment.hex`, `c_new.hex`

use sha_fri::air::{digest_to_bytes, Kind};
use sha_fri::hash::Sha2Hasher;
use sha_fri::params::{deployment_params, Profile};
use sha_fri::{prover, verifier};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn be32(epoch: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&epoch.to_be_bytes());
    out
}

fn write(dir: &Path, proof: &[u8], pis: &[[u8; 32]]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("proof.bin"), proof)?;
    let items: Vec<String> = pis.iter().map(|p| format!("\"{}\"", hex(p))).collect();
    std::fs::write(dir.join("public_inputs.json"), format!("[{}]\n", items.join(",")))
}

fn main() -> ExitCode {
    let mut depth = None;
    let mut profile = Profile::Johnson100;
    let mut seed = 1u64;
    let mut out_dir = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().unwrap_or_default();
        match flag.as_str() {
            "--depth" => depth = value.parse::<u8>().ok(),
            "--profile" => {
                profile = match value.as_str() {
                    "johnson" => Profile::Johnson100,
                    "conjectured" => Profile::Conjectured100,
                    _ => {
                        eprintln!("--profile must be johnson or conjectured");
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--seed" => seed = value.parse().unwrap_or(1),
            "--out-dir" => out_dir = Some(PathBuf::from(value)),
            other => {
                eprintln!("unknown flag {other}");
                return ExitCode::FAILURE;
            }
        }
    }
    let (Some(depth), Some(out_dir)) = (depth, out_dir) else {
        eprintln!("usage: gen-pq-anarchy-bundle --depth 5|8|11 [--profile johnson|conjectured] [--seed N] --out-dir DIR");
        return ExitCode::FAILURE;
    };

    // ---- create: membership at epoch 0 ------------------------------
    let member = prover::random_witness(depth as usize, seed, 0);
    let p = deployment_params(Kind::Membership, depth, profile);
    let create_proof = prover::prove(&Sha2Hasher, &p, &member, seed ^ 0xC0FFEE);
    let pi = member.public_inputs();
    verifier::verify(&Sha2Hasher, &p.to_bytes(), &create_proof, &pi.to_bytes()).expect("create self-verify");
    let commitment = digest_to_bytes(&pi.commitment);

    // ---- update: same member, epoch 0 → 1 ---------------------------
    let upd = prover::with_random_update(prover::random_witness(depth as usize, seed, 0), seed);
    let pu = deployment_params(Kind::Update, depth, profile);
    let update_proof = prover::prove(&Sha2Hasher, &pu, &upd, seed ^ 0xBEEF);
    let upi = upd.public_inputs();
    verifier::verify(&Sha2Hasher, &pu.to_bytes(), &update_proof, &upi.to_bytes()).expect("update self-verify");
    assert_eq!(digest_to_bytes(&upi.commitment), commitment, "update does not chain from create");
    let c_new = digest_to_bytes(&upi.c_new.unwrap());

    let io = || -> std::io::Result<()> {
        write(&out_dir.join("create"), &create_proof, &[commitment, be32(0)])?;
        write(&out_dir.join("update"), &update_proof, &[commitment, be32(0), c_new])?;
        std::fs::write(out_dir.join("commitment.hex"), hex(&commitment))?;
        std::fs::write(out_dir.join("c_new.hex"), hex(&c_new))
    };
    if let Err(e) = io() {
        eprintln!("write failed: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!(
        "[gen-pq-anarchy-bundle] d={depth} {profile:?}: create {} B, update {} B → {}",
        create_proof.len(),
        update_proof.len(),
        out_dir.display()
    );
    ExitCode::SUCCESS
}
