//! `cargo run --release -- <path/to/pq_sha_fri_bench_contract.wasm>`
//!
//! For each preset: prove (timed), verify natively, then invoke the
//! bench contract's `verify` in a metered host and record CPU
//! instructions and memory bytes. Caps are the live futurenet/testnet
//! values (`contract_compute_v0`, `contract_bandwidth_v0`, read
//! 2026-11-11 via getLedgerEntries).

use sha_fri::hash::Sha2Hasher;
use sha_fri::params::Params;
use sha_fri::{prover, verifier};
use soroban_sdk::{Bytes, Env, IntoVal, Symbol, Val};
use std::time::Instant;

const TX_MAX_INSTRUCTIONS: u64 = 400_000_000;
const TX_MEMORY_LIMIT: u64 = 41_943_040;
const TX_MAX_SIZE_BYTES: usize = 132_096;

struct Preset {
    name: &'static str,
    params: Params,
}

fn preset(
    name: &'static str,
    log_trace_rows: u8,
    num_cols: u16,
    log_blowup: u8,
    num_queries: u16,
    grind_bits: u8,
    log_arities: &[u8],
) -> Preset {
    Preset {
        name,
        params: Params {
            log_trace_rows,
            num_cols,
            log_blowup,
            num_queries,
            grind_bits,
            cap_height: 4,
            log_arities: log_arities.to_vec(),
        },
    }
}

fn presets() -> Vec<Preset> {
    vec![
        // ~2^9 rows × 48 cols: a row-per-round Poseidon2 AIR over 11
        // Merkle levels (sep-anarchy depth 11) plus quotient chunks.
        preset("membership d11, conjectured", 9, 48, 4, 20, 20, &[1, 3, 3]),
        preset("membership d11, Johnson", 9, 48, 4, 40, 20, &[1, 3, 3]),
        preset("4× circuit (2^11 rows), Johnson", 11, 48, 4, 40, 20, &[1, 3, 3, 3]),
        preset("32× circuit (2^14 rows), Johnson", 14, 48, 4, 40, 20, &[1, 3, 3, 3, 3]),
        preset("rate 1/2 (blowup 2), conjectured", 9, 48, 1, 80, 20, &[1, 3, 3]),
        preset("wide trace (400 cols), Johnson", 5, 400, 4, 40, 20, &[1, 3]),
    ]
}

struct Metered {
    ok: bool,
    cpu: u64,
    mem: u64,
}

fn invoke(env: &Env, wasm: &[u8], params: &[u8], proof: &[u8], pi: &[u8]) -> Metered {
    let id = env.register(wasm, ());
    let args: soroban_sdk::Vec<Val> = soroban_sdk::vec![
        env,
        Bytes::from_slice(env, params).into_val(env),
        Bytes::from_slice(env, proof).into_val(env),
        Bytes::from_slice(env, pi).into_val(env),
    ];
    env.cost_estimate().budget().reset_unlimited();
    let ok: bool = env.invoke_contract(&id, &Symbol::new(env, "verify"), args);
    let budget = env.cost_estimate().budget();
    Metered { ok, cpu: budget.cpu_instruction_cost(), mem: budget.memory_bytes_cost() }
}

fn pct(x: u64, cap: u64) -> String {
    format!("{:.1}%", x as f64 * 100.0 / cap as f64)
}

fn main() {
    let wasm_path = std::env::args().nth(1).expect("usage: pq-sha-fri-runner <bench.wasm>");
    let wasm = std::fs::read(&wasm_path).expect("read wasm");
    let pi = [0x42u8; 32];

    println!("| Preset | Trace | Blowup | Queries | Grind | Security (conj / Johnson) | Proof bytes | % tx size | CPU insns | % CPU cap | Mem bytes | % mem cap | Prove ms |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|");

    for (i, pr) in presets().into_iter().enumerate() {
        let p = &pr.params;
        let pb = p.to_bytes();

        let t0 = Instant::now();
        let proof = prover::prove(&Sha2Hasher, p, &pi, 0x5eed + i as u64);
        let prove_ms = t0.elapsed().as_millis();

        verifier::verify(&Sha2Hasher, &pb, &proof, &pi).expect("native verify");

        let env = Env::default();
        let m = invoke(&env, &wasm, &pb, &proof, &pi);
        assert!(m.ok, "{}: on-chain verify rejected an honest proof", pr.name);

        // Bytes args ride inside the tx envelope; ~1 KB covers the
        // envelope, auth, footprint and signature overhead.
        let tx_bytes = proof.len() + pb.len() + pi.len() + 1024;

        println!(
            "| {} | 2^{} × {} | {} | {} | {} | {} / {} bits | {} | {} | {} | {} | {} | {} | {} |",
            pr.name,
            p.log_trace_rows,
            p.num_cols,
            1u32 << p.log_blowup,
            p.num_queries,
            p.grind_bits,
            p.conjectured_security_bits(),
            p.johnson_security_bits(),
            proof.len(),
            pct(tx_bytes as u64, TX_MAX_SIZE_BYTES as u64),
            m.cpu,
            pct(m.cpu, TX_MAX_INSTRUCTIONS),
            m.mem,
            pct(m.mem, TX_MEMORY_LIMIT),
            prove_ms,
        );

        if i == 0 {
            // Rejection path: flip one byte inside the query section.
            let mut bad = proof.clone();
            let at = bad.len() - 200;
            bad[at] ^= 1;
            let env = Env::default();
            let r = invoke(&env, &wasm, &pb, &bad, &pi);
            assert!(!r.ok, "tampered proof accepted on-chain");
            eprintln!("tamper check: rejected on-chain ({} insns)", r.cpu);
        }
    }
}
