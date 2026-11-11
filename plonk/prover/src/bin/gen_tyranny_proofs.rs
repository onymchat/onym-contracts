//! Generate a chained sep-tyranny `create_group` → `update_commitment`
//! proof bundle for the testnet gas bench.
//!
//! ```text
//!     cargo run --release --bin gen-tyranny-proofs -- \
//!         --depth 5 --group-id 0x7778 --out-dir ./tyranny-d5
//! ```
//!
//! The committed `tyranny-{create,update}-*` fixtures don't chain: the
//! update fixture is baked at `epoch_old = 1234` against a different
//! `c_old`, and both pin `group_id_fr = 0x7777`, so one deployment can
//! host only one of them. This binary uses the same canonical roster
//! (keys 1..=8, admin at index 0, salt_old 0xEE, salt_new 0xFF) with a
//! caller-chosen group id, and `epoch_old = 0`, so `update.c_old` equals
//! `create.commitment` byte for byte.
//!
//! A membership proof for the post-create state comes from
//! `gen-membership-proof --epoch 0 --salt 0xEE… --secret-keys 1..8`:
//! the commitment depends only on (root, epoch, salt).
//!
//! Writes to `<out-dir>`:
//! - `create/proof.hex`, `create/public_inputs.json`
//!   (`[commitment, epoch=0, admin_pubkey_commitment, group_id_fr]`)
//! - `update/proof.hex`, `update/public_inputs.json`
//!   (`[c_old, epoch_old=0, c_new, admin_pubkey_commitment, group_id_fr]`)
//! - `group_id.hex`, `commitment.hex`, `admin_pubkey_commitment.hex`
//!
//! Each proof is self-verified against a freshly preprocessed VK before
//! it is written; VK shape depends only on depth, so it matches the
//! per-tier VKs baked into the contract.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ark_bls12_381_v05::Fr;
use ark_ff_v05::{BigInteger, PrimeField};
use ark_serialize_v05::CanonicalSerialize;
use jf_relation::PlonkCircuit;
use rand_chacha::rand_core::SeedableRng;

use onym_plonk_prover::circuit::plonk::baker::{
    build_tyranny_create_witness, build_tyranny_update_witness,
};
use onym_plonk_prover::circuit::plonk::tyranny::{
    synthesize_tyranny_create, synthesize_tyranny_update,
};
use onym_plonk_prover::prover::plonk;

mod common;
use common::{decode_hex, write_bin_and_hex, CliError};

struct Args {
    depth: usize,
    group_id: Fr,
    out_dir: PathBuf,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), CliError> {
    let args = parse_args()?;

    // ---- create_group (epoch 0) -------------------------------------
    let cw = build_tyranny_create_witness(args.depth, args.group_id);
    let create_pi = vec![cw.commitment, Fr::from(0u64), cw.admin_pubkey_commitment, cw.group_id_fr];
    let mut circuit = PlonkCircuit::<Fr>::new_turbo_plonk();
    synthesize_tyranny_create(&mut circuit, &cw).map_err(CliError::circuit)?;
    let create_proof = prove_and_check(circuit, &create_pi, "create")?;
    write_bundle(&args.out_dir.join("create"), &create_proof, &create_pi)?;

    // ---- update_commitment (epoch_old 0 → 1) ------------------------
    let uw = build_tyranny_update_witness(args.depth, 0, args.group_id);
    if uw.c_old != cw.commitment || uw.admin_pubkey_commitment != cw.admin_pubkey_commitment {
        return Err(CliError::other("update witness does not chain from create witness"));
    }
    let update_pi = vec![
        uw.c_old,
        Fr::from(uw.epoch_old),
        uw.c_new,
        uw.admin_pubkey_commitment,
        uw.group_id_fr,
    ];
    let mut circuit = PlonkCircuit::<Fr>::new_turbo_plonk();
    synthesize_tyranny_update(&mut circuit, &uw).map_err(CliError::circuit)?;
    let update_proof = prove_and_check(circuit, &update_pi, "update")?;
    write_bundle(&args.out_dir.join("update"), &update_proof, &update_pi)?;

    write_bin_and_hex(&args.out_dir, "group_id", &fr_to_be32(&cw.group_id_fr))?;
    write_bin_and_hex(&args.out_dir, "commitment", &fr_to_be32(&cw.commitment))?;
    write_bin_and_hex(
        &args.out_dir,
        "admin_pubkey_commitment",
        &fr_to_be32(&cw.admin_pubkey_commitment),
    )?;
    eprintln!(
        "[gen-tyranny-proofs] depth={} group_id={} → {}",
        args.depth,
        hex(&fr_to_be32(&cw.group_id_fr)),
        args.out_dir.display()
    );
    Ok(())
}

fn prove_and_check(
    mut circuit: PlonkCircuit<Fr>,
    public_inputs: &[Fr],
    label: &str,
) -> Result<Vec<u8>, CliError> {
    circuit.finalize_for_arithmetization().map_err(CliError::circuit)?;
    eprintln!(
        "[gen-tyranny-proofs] {label}: {} gates",
        jf_relation::Circuit::num_gates(&circuit)
    );
    let keys = plonk::preprocess(&circuit).map_err(CliError::plonk)?;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);
    let proof = plonk::prove(&mut rng, &keys.pk, &circuit).map_err(CliError::plonk)?;
    plonk::verify(&keys.vk, public_inputs, &proof).map_err(|e| {
        CliError::other(format!("{label}: self-verify rejected proof: {e:?}"))
    })?;
    let mut bytes = Vec::new();
    proof.serialize_uncompressed(&mut bytes).map_err(CliError::serialize)?;
    if bytes.len() != 1601 {
        return Err(CliError::other(format!("{label}: unexpected proof length {}", bytes.len())));
    }
    Ok(bytes)
}

fn write_bundle(dir: &Path, proof: &[u8], public_inputs: &[Fr]) -> Result<(), CliError> {
    fs::create_dir_all(dir).map_err(CliError::io)?;
    write_bin_and_hex(dir, "proof", proof)?;
    let items: Vec<String> = public_inputs.iter().map(|f| format!("\"{}\"", hex(&fr_to_be32(f)))).collect();
    fs::write(dir.join("public_inputs.json"), format!("[{}]\n", items.join(","))).map_err(CliError::io)
}

fn parse_args() -> Result<Args, CliError> {
    let mut depth = None;
    let mut group_id = None;
    let mut out_dir = None;
    let mut it = env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| CliError::usage(format!("{flag} needs a value")));
        match flag.as_str() {
            "--depth" => {
                let v = value()?;
                depth = Some(v.parse::<usize>().map_err(|_| CliError::usage(format!("bad --depth {v}")))?);
            }
            "--group-id" => {
                let bytes = decode_hex(&value()?)?;
                if bytes.len() > 31 {
                    return Err(CliError::usage("--group-id must fit in 31 bytes (canonical Fr)"));
                }
                group_id = Some(Fr::from_be_bytes_mod_order(&bytes));
            }
            "--out-dir" => out_dir = Some(PathBuf::from(value()?)),
            other => return Err(CliError::usage(format!("unknown flag {other}"))),
        }
    }
    let depth = depth.ok_or_else(|| CliError::usage("--depth is required (5, 8 or 11)"))?;
    if ![5, 8, 11].contains(&depth) {
        return Err(CliError::usage(format!("--depth {depth} unsupported (5, 8 or 11)")));
    }
    Ok(Args {
        depth,
        group_id: group_id.ok_or_else(|| CliError::usage("--group-id is required"))?,
        out_dir: out_dir.ok_or_else(|| CliError::usage("--out-dir is required"))?,
    })
}

fn fr_to_be32(f: &Fr) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
