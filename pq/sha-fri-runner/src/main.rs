//! `cargo run --release -- <path/to/pq_sha_fri_bench_contract.wasm>`
//!
//! For each preset: build a random membership witness, prove (timed),
//! verify natively, then invoke the bench contract's `verify` in a
//! metered host and record CPU instructions and memory bytes. Caps are
//! the live futurenet/testnet values (`contract_compute_v0`,
//! `contract_bandwidth_v0`, read 2026-11-11 via getLedgerEntries).

use sha_fri::air::Kind;
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

/// Layer-0 arity 2, then arity 8 until the final polynomial is a constant.
fn arities(log_n0: u32, log_blowup: u8) -> Vec<u8> {
    let mut rem = log_n0 - 1 - log_blowup as u32;
    let mut out = vec![1u8];
    while rem > 0 {
        let a = rem.min(3);
        out.push(a as u8);
        rem -= a;
    }
    out
}

fn preset(name: &'static str, depth: u8, log_blowup: u8, num_queries: u16, grind_bits: u8) -> Preset {
    let mut params = Params {
        kind: Kind::Membership,
        depth,
        // Minimum for hiding: every revealed evaluation is covered.
        mask_degree: num_queries * 2 + 2,
        log_blowup,
        num_queries,
        grind_bits,
        cap_height: 4,
        log_arities: vec![1],
    };
    params.log_arities = arities(params.log_n0(), log_blowup);
    params.validate().unwrap_or_else(|_| panic!("{name}: invalid params"));
    Preset { name, params }
}

fn presets() -> Vec<Preset> {
    vec![
        preset("d5, blowup 16, conjectured", 5, 4, 20, 20),
        preset("d8, blowup 16, conjectured", 8, 4, 20, 20),
        preset("d11, blowup 16, conjectured", 11, 4, 20, 20),
        preset("d5, blowup 16, Johnson", 5, 4, 40, 20),
        preset("d8, blowup 16, Johnson", 8, 4, 40, 20),
        preset("d11, blowup 16, Johnson", 11, 4, 40, 20),
        preset("d11, blowup 8, Johnson", 11, 3, 54, 20),
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

    println!("| Preset | Trace rows | Quotient chunks | Queries | Security (conj / Johnson) | Proof bytes | % tx size | CPU insns | % CPU cap | Mem bytes | % mem cap | Prove ms |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|");

    for (i, pr) in presets().into_iter().enumerate() {
        let p = &pr.params;
        let pb = p.to_bytes();
        let w = prover::random_witness(p.depth as usize, 0x5eed + i as u64, 0x1234_5678_9abc);
        let pi = w.public_inputs().to_bytes();

        let t0 = Instant::now();
        let proof = prover::prove(&Sha2Hasher, p, &w, 0xC0FFEE + i as u64);
        let prove_ms = t0.elapsed().as_millis();

        verifier::verify(&Sha2Hasher, &pb, &proof, &pi).expect("native verify");

        let env = Env::default();
        let m = invoke(&env, &wasm, &pb, &proof, &pi);
        assert!(m.ok, "{}: on-chain verify rejected an honest proof", pr.name);

        // Bytes args ride inside the tx envelope; ~1 KB covers the
        // envelope, auth, footprint and signature overhead.
        let tx_bytes = proof.len() + pb.len() + pi.len() + 1024;

        println!(
            "| {} | {} | {} | {} | {} / {} bits | {} | {} | {} | {} | {} | {} | {} |",
            pr.name,
            p.n(),
            p.num_quotient_chunks(),
            p.num_queries,
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
            // Rejection paths on-chain: tampered query bytes, wrong epoch.
            let mut bad = proof.clone();
            let at = bad.len() - 200;
            bad[at] ^= 1;
            let r = invoke(&Env::default(), &wasm, &pb, &bad, &pi);
            assert!(!r.ok, "tampered proof accepted on-chain");
            let mut wrong_pi = pi;
            wrong_pi[32] ^= 1;
            let r2 = invoke(&Env::default(), &wasm, &pb, &proof, &wrong_pi);
            assert!(!r2.ok, "wrong epoch accepted on-chain");
            eprintln!("rejections on-chain: tampered ({} insns), wrong epoch ({} insns)", r.cpu, r2.cpu);
        }
    }
}
