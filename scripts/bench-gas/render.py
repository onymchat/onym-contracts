#!/usr/bin/env python3
"""Render the bench JSONL into a Markdown release body.

Input:  one JSON object per line, schema produced by `lib.sh`'s
        `emit_row` (row_type=op) + `emit_contract_address`
        (row_type=contract).
Output: a single Markdown document — contract-address table (with
        stellar.expert links) above the gas table.

The workflow uses this output directly as the GitHub release body
(`body_path:` for softprops/action-gh-release@v2), not as an asset.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

CONTRACT_ORDER = {
    "sep-anarchy": 0,
    "sep-democracy": 1,
    "sep-oligarchy": 2,
    "sep-oneonone": 3,
    "sep-tyranny": 4,
    # PQ flavor — sorted after PLONK so a mixed-flavor JSONL (if it
    # ever happens) puts PLONK rows on top.
    "pq-sep-anarchy": 10,
}

OP_ORDER = {
    "deploy": 0,
    "create_group": 1,
    "create_oligarchy_group": 1,
    "verify_membership": 2,
    "update_commitment": 3,
    "set_restricted_mode": 10,
    "bump_group_ttl": 11,
}

NETWORK_TO_EXPERT = {
    "testnet": "https://stellar.expert/explorer/testnet",
    "public": "https://stellar.expert/explorer/public",
    "mainnet": "https://stellar.expert/explorer/public",
}


def stroops_to_xlm(stroops: int | None) -> str:
    if stroops is None:
        return "—"
    return f"{stroops / 10_000_000:.7f}"


def fmt_stroops(stroops: int | None) -> str:
    if stroops is None:
        return "—"
    return f"{stroops:,}"


def fmt_int(value: int | None) -> str:
    if value is None:
        return "—"
    return f"{int(value):,}"


def tier_str(t: str) -> str:
    if t in ("", "n/a", "none", None):
        return "—"
    return t


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--jsonl", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--network", default="testnet")
    p.add_argument("--tag", default="(untagged)")
    return p.parse_args()


def load_rows(path: Path) -> tuple[list[dict], list[dict]]:
    """Returns (op_rows, contract_rows)."""
    op_rows: list[dict] = []
    contract_rows: list[dict] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"warning: skipping unparseable line: {exc}", file=sys.stderr)
                continue
            row_type = row.get("row_type")
            if row_type == "contract":
                contract_rows.append(row)
            else:
                # row_type=op or absent (legacy schema)
                op_rows.append(row)
    return op_rows, contract_rows


def sort_op(row: dict) -> tuple:
    return (
        CONTRACT_ORDER.get(row.get("contract", ""), 99),
        OP_ORDER.get(row.get("op", ""), 99),
        row.get("tier") or "",
    )


def sort_contract(row: dict) -> int:
    return CONTRACT_ORDER.get(row.get("contract", ""), 99)


def truncate_addr(addr: str) -> str:
    if len(addr) <= 16:
        return addr
    return f"{addr[:6]}…{addr[-6:]}"


def build_contract_table(contract_rows: list[dict], network: str) -> str:
    if not contract_rows:
        return "_(no contracts deployed)_"

    expert = NETWORK_TO_EXPERT.get(network, NETWORK_TO_EXPERT["testnet"])
    lines = [
        "| Contract | Address |",
        "|---|---|",
    ]
    for row in sorted(contract_rows, key=sort_contract):
        addr = row.get("address", "")
        contract = row.get("contract", "?")
        if not addr:
            lines.append(f"| `{contract}` | _(deploy failed)_ |")
            continue
        link = f"[`{truncate_addr(addr)}`]({expert}/contract/{addr})"
        lines.append(f"| `{contract}` | {link} |")
    return "\n".join(lines)


def build_gas_table(op_rows: list[dict]) -> str:
    if not op_rows:
        return "_(no transactions submitted)_"

    # `Fee (XLM)` and `Stroops` are the same number in different units —
    # `Resource` + `Inclusion` add up to `Stroops`. `Non-refundable` is
    # the locked portion of `Resource`; `Refundable` is the rest of
    # `Resource` (charged up-front, refunded if unused — but already
    # netted out in the headline `Stroops`).
    headers = ["Contract", "Operation", "Tier", "Fee (XLM)",
               "Stroops", "Resource", "Non-refundable", "Refundable", "Inclusion"]
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in sorted(op_rows, key=sort_op):
        cells = [
            f"`{row.get('contract', '?')}`",
            f"`{row.get('op', '?')}`",
            tier_str(row.get("tier", "")),
            stroops_to_xlm(row.get("fee_stroops")),
            fmt_stroops(row.get("fee_stroops")),
            fmt_int(row.get("resource_fee")),
            fmt_int(row.get("non_refundable_resource_fee")),
            fmt_int(row.get("refundable_resource_fee")),
            fmt_int(row.get("inclusion_fee")),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


PLONK_CONTRACTS = {
    "sep-anarchy",
    "sep-democracy",
    "sep-oligarchy",
    "sep-oneonone",
    "sep-tyranny",
}
PQ_CONTRACTS = {"pq-sep-anarchy"}


def detect_flavor(contract_rows: list[dict], op_rows: list[dict]) -> str:
    """Returns 'plonk', 'pq', or 'mixed' based on which contract names
    appear in the JSONL. Used to choose the explanatory notes block —
    PLONK and PQ have very different reasons their revert-mode rows
    show up the way they do, and the bottom-section notes need to
    reflect the right one."""
    seen = {row.get("contract", "") for row in contract_rows}
    seen.update(row.get("contract", "") for row in op_rows)
    has_plonk = bool(seen & PLONK_CONTRACTS)
    has_pq = bool(seen & PQ_CONTRACTS)
    if has_plonk and has_pq:
        return "mixed"
    if has_pq:
        return "pq"
    return "plonk"


def notes_for_flavor(flavor: str) -> list[str]:
    common = ["- Stroops are testnet stroops; 1 XLM = 10,000,000 stroops."]
    if flavor == "pq":
        return common + [
            "- `create_group` / `verify_membership` / `update_commitment` rows "
            "are real on-chain FRI verifications: the off-chain `gen-pq-proof` "
            "binary in `pq/prover/` produces self-consistent FRI proofs the "
            "on-chain verifier accepts at bench-scope parameters "
            "(log_n=6, num_layers=3, num_queries=8, blowup=2). Proof size: "
            "~8 KB.",
            "- These numbers are **bench-scope only**: the on-chain verifier "
            "today runs the FRI low-degree test alone, with no batched-PCS "
            "layer tying FRI to an AIR. So the proofs prove "
            "\"prover committed to a low-degree polynomial\" and nothing more — "
            "they do not encode any circuit witness. Do **not** deploy the "
            "contract behind this verifier for production; the `verifier_pcs` "
            "follow-up is the gating dependency.",
            "- `set_restricted_mode` second toggle is cheaper than the first "
            "because the storage slot already exists by then (the second write "
            "skips creation overhead).",
            "- `verify_membership` is read-only and does not consume the global "
            "nullifier — the same proof bytes can be re-submitted without "
            "burning `UsedProof` storage. Same convention as the PLONK flavor.",
            "- See `pq/verifier/src/lib.rs` for the open-work list: batched "
            "PCS layer, prover-side fixtures from a real circuit, canonical "
            "Plonky3 Poseidon2 round constants.",
        ]
    if flavor == "plonk":
        return common + [
            "- `verify_membership` rows for `sep-oligarchy` are captured in revert-mode "
            "(well-formed proof, non-matching PI); the verifier returns `Ok(false)` "
            "on `InvalidProof` without reverting, so the captured fee equals the "
            "success-path cost. Rows for `sep-anarchy` and `sep-democracy` use real "
            "verifying proofs (V2).",
            "- `update_commitment` for `sep-anarchy` uses real proofs via "
            "`gen-update-proof` and captures the full success-path cost including "
            "post-verify storage writes.",
            "- `sep-tyranny` and the `update_commitment` rows for `sep-democracy` / "
            "`sep-oligarchy` / `sep-oneonone.verify_membership` are deferred to V3 — "
            "they need contract-specific proof generators that don't exist yet.",
        ]
    # mixed
    return common + [
        "- This run includes both PLONK and PQ contracts; rows for each flavor "
        "follow that flavor's bench-mode conventions. See the per-flavor "
        "bench-gas drivers for which entrypoints are revert-mode vs. real-proof."
    ]


def main() -> int:
    args = parse_args()
    op_rows, contract_rows = load_rows(args.jsonl)

    captured_at = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    flavor = detect_flavor(contract_rows, op_rows)
    title_suffix = {"pq": " (PQ)", "plonk": "", "mixed": " (mixed)"}[flavor]

    body_lines = [
        f"# SEP MLS testnet gas benchmarks{title_suffix} — {args.tag}",
        "",
        f"- **Network:** {args.network}",
        f"- **Captured:** {captured_at}",
        f"- **Op rows:** {len(op_rows)}    **Contracts deployed:** {len(contract_rows)}",
        "",
        "## Deployed contracts",
        "",
        build_contract_table(contract_rows, args.network),
        "",
        "## Per-op gas costs",
        "",
        build_gas_table(op_rows),
        "",
        "## Notes",
        "",
        *notes_for_flavor(flavor),
    ]

    args.output.write_text("\n".join(body_lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
