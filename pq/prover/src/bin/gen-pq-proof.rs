//! `gen-pq-proof` — emit a FRI proof + bench-compatible artefacts.
//!
//! Output files (drop-in compatible with `lib.sh`'s
//! `bench_gen_proof_hex` / `bench_gen_pi_json` / `bench_gen_commitment_hex`
//! helpers used by the PLONK bench drivers):
//!   - `proof.bin`            raw FRI proof bytes
//!   - `proof.hex`            same, hex-encoded one line
//!   - `commitment.hex`       32-byte commitment (membership) or c_new (update)
//!   - `public_inputs.json`   `["<32-byte hex>", …]`
//!
//! ## Circuits
//!
//! * `--circuit membership` — 2 PIs: `(commitment, epoch)`.
//!   Membership proofs are used by `create_group` (epoch=0) and
//!   `verify_membership` (epoch=current).
//! * `--circuit update` — 3 PIs: `(c_old, epoch_old, c_new)`.
//!
//! The on-chain verifier checks public-input equality with what the
//! contract stored, so the args here must match what the bench
//! driver passes to the contract entrypoint.
//!
//! ## Bench-only safety note
//!
//! This prover is **not** a circuit-binding prover — it produces
//! self-consistent FRI proofs that verify under the on-chain
//! verifier's *low-degree* check, but without a batched-PCS layer
//! tying FRI to an AIR there is no constraint system. Use only for
//! gas measurement.

use clap::Parser;
use pq_fri_prover::fri_prover::prove;
use pq_fri_prover::proof_bytes::serialize_proof;
use soroban_sdk::Env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Clone, clap::ValueEnum)]
enum Circuit {
    Membership,
    Update,
}

#[derive(Parser, Debug)]
#[command(about = "PQ FRI proof generator (bench-only)")]
struct Args {
    /// Membership = 2 PIs (commitment, epoch). Update = 3 PIs.
    #[arg(long, value_enum)]
    circuit: Circuit,

    /// `commitment` for membership. Required for both circuits — for
    /// update, this is `c_old` (must equal the contract's stored
    /// commitment for that group).
    #[arg(long, value_parser = parse_hex32)]
    commitment: [u8; 32],

    /// `epoch` (membership) or `epoch_old` (update). Hex bytes,
    /// 32-byte BE u64 layout (matches `be32_from_u64`).
    #[arg(long, default_value = "0", value_parser = parse_u64)]
    epoch: u64,

    /// `c_new` — only used for `--circuit update`.
    #[arg(long, value_parser = parse_hex32)]
    new_commitment: Option<[u8; 32]>,

    /// Output directory. Files: proof.bin, proof.hex, commitment.hex,
    /// public_inputs.json.
    #[arg(long)]
    out_dir: PathBuf,
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return Err(format!("expected 32 bytes (64 hex chars), got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("bad hex at byte {i}: {e}"))?;
        out[i] = byte;
    }
    Ok(out)
}

fn parse_u64(s: &str) -> Result<u64, String> {
    s.parse::<u64>().map_err(|e| e.to_string())
}

fn be32_from_u64(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn pi_to_le_lanes(pi: &[u8; 32]) -> [[u8; 4]; 8] {
    let mut out = [[0u8; 4]; 8];
    for j in 0..8 {
        let off = j * 4;
        out[j].copy_from_slice(&pi[off..off + 4]);
    }
    out
}

fn flatten_pi(pis: &[[u8; 32]]) -> Vec<[u8; 4]> {
    let mut out = Vec::with_capacity(pis.len() * 8);
    for pi in pis.iter() {
        for lane in pi_to_le_lanes(pi).iter() {
            out.push(*lane);
        }
    }
    out
}

fn json_array(pis: &[[u8; 32]]) -> String {
    let mut s = String::from("[");
    for (i, pi) in pis.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        for b in pi.iter() {
            use std::fmt::Write;
            let _ = write!(&mut s, "{:02x}", b);
        }
        s.push('"');
    }
    s.push(']');
    s
}

fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    use std::fmt::Write;
    for b in bytes.iter() {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

fn main() -> ExitCode {
    let args = Args::parse();

    let pis: Vec<[u8; 32]> = match args.circuit {
        Circuit::Membership => vec![args.commitment, be32_from_u64(args.epoch)],
        Circuit::Update => {
            let Some(c_new) = args.new_commitment else {
                eprintln!("--new-commitment required for --circuit update");
                return ExitCode::from(2);
            };
            vec![args.commitment, be32_from_u64(args.epoch), c_new]
        }
    };

    let pi_le = flatten_pi(&pis);

    let env = Env::default();
    let witness = prove(&env, &pi_le);
    let proof_bytes = serialize_proof(&witness);

    if let Err(e) = fs::create_dir_all(&args.out_dir) {
        eprintln!("create out dir: {e}");
        return ExitCode::from(1);
    }
    let out = |name: &str| args.out_dir.join(name);

    if let Err(e) = fs::write(out("proof.bin"), &proof_bytes) {
        eprintln!("write proof.bin: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = fs::write(out("proof.hex"), hex_string(&proof_bytes)) {
        eprintln!("write proof.hex: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = fs::write(out("commitment.hex"), hex_string(&args.commitment)) {
        eprintln!("write commitment.hex: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = fs::write(out("public_inputs.json"), json_array(&pis)) {
        eprintln!("write public_inputs.json: {e}");
        return ExitCode::from(1);
    }

    eprintln!(
        "wrote {} bytes of proof to {}",
        proof_bytes.len(),
        args.out_dir.display()
    );
    ExitCode::SUCCESS
}
