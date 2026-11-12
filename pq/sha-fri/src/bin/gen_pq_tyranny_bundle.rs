//! Chained `create_group` → `verify_membership` → `update_commitment`
//! proof bundle for the `pq/sep-tyranny` testnet bench (`Pq100`).
//!
//! ```text
//!   cargo run --release --features prover,ext8 --bin gen-pq-tyranny-bundle -- \
//!       --depth 11 --group 2 --seed 7 --out-dir ./bundle
//! ```
//!
//! One random admin at epoch 0 proves `AdminCreate` for group `--group`,
//! a `Membership` proof for the same state (any member works; this uses
//! the admin's own leaf), then `AdminUpdate` to a random new root/salt at
//! epoch 1, so `update.c_old == create.commitment` and the admin
//! commitment matches.
//!
//! Writes (`public_inputs.json` is the contract's `Vec<BytesN<32>>`:
//! digests as 8 × u32 LE, epochs as 32-byte big-endian):
//! - `create/proof.bin`, `create/public_inputs.json`  `[c, be32(0), admin_comm, group_id]`
//! - `member/proof.bin`, `member/public_inputs.json`  `[c, be32(0)]`
//! - `update/proof.bin`, `update/public_inputs.json`  `[c, be32(0), c_new, admin_comm, group_id]`
//! - `group_id.hex`, `commitment.hex`, `admin_comm.hex`

use sha_fri::air::{digest_to_bytes, Kind};
use sha_fri::field::F;
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

fn prove(kind: Kind, depth: u8, w: &sha_fri::air::Witness) -> Vec<u8> {
    let p = deployment_params(kind, depth, Profile::Pq100);
    // OS-entropy masking randomness, exactly as a real client proves.
    let proof = prover::prove(&Sha2Hasher, &p, w);
    verifier::verify(&Sha2Hasher, &p.to_bytes(), &proof, &w.public_inputs().to_bytes())
        .unwrap_or_else(|e| panic!("{kind:?} self-verify: {e:?}"));
    proof
}

fn main() -> ExitCode {
    let (mut depth, mut group, mut seed, mut out_dir) = (None, 1u64, 1u64, None);
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().unwrap_or_default();
        match flag.as_str() {
            "--depth" => depth = value.parse::<u8>().ok(),
            "--group" => group = value.parse().unwrap_or(1),
            "--seed" => seed = value.parse().unwrap_or(1),
            "--out-dir" => out_dir = Some(PathBuf::from(value)),
            other => {
                eprintln!("unknown flag {other}");
                return ExitCode::FAILURE;
            }
        }
    }
    let (Some(depth), Some(out_dir)) = (depth, out_dir) else {
        eprintln!("usage: gen-pq-tyranny-bundle --depth 5|8|11 [--group N] [--seed N] --out-dir DIR");
        return ExitCode::FAILURE;
    };
    let gid: [F; 8] = core::array::from_fn(|i| F::from_u64(0x7777_0000 + group * 16 + i as u64));
    let base = || prover::random_witness(depth as usize, seed, 0);

    let admin = prover::with_admin(base(), gid);
    let pi = admin.public_inputs();
    let create = prove(Kind::AdminCreate, depth, &admin);
    let member = prove(Kind::Membership, depth, &base());
    let upd = prover::with_admin(prover::with_random_update(base(), seed), gid);
    let update = prove(Kind::AdminUpdate, depth, &upd);

    let c = digest_to_bytes(&pi.commitment);
    let a = digest_to_bytes(&pi.admin.unwrap().0);
    let g = digest_to_bytes(&gid);
    let upi = upd.public_inputs();
    assert_eq!(digest_to_bytes(&upi.commitment), c, "update does not chain from create");
    let c_new = digest_to_bytes(&upi.c_new.unwrap());

    let io = || -> std::io::Result<()> {
        write(&out_dir.join("create"), &create, &[c, be32(0), a, g])?;
        write(&out_dir.join("member"), &member, &[c, be32(0)])?;
        write(&out_dir.join("update"), &update, &[c, be32(0), c_new, a, g])?;
        std::fs::write(out_dir.join("group_id.hex"), hex(&g))?;
        std::fs::write(out_dir.join("commitment.hex"), hex(&c))?;
        std::fs::write(out_dir.join("admin_comm.hex"), hex(&a))
    };
    if let Err(e) = io() {
        eprintln!("write failed: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!(
        "[gen-pq-tyranny-bundle] d={depth}: create {} B, member {} B, update {} B → {}",
        create.len(),
        member.len(),
        update.len(),
        out_dir.display()
    );
    ExitCode::SUCCESS
}
