#!/usr/bin/env python3
"""Generate contracts-manifest.json from onym-contracts releases."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CONTRACT_ORDER = ["anarchy", "democracy", "oligarchy", "oneonone", "tyranny"]
NETWORKS = {
    "testnet": "testnet",
    "public": "public",
    "mainnet": "public",
    "pubnet": "public",
}
NETWORK_RE = re.compile(r"\*\*Network:\*\*\s*([A-Za-z0-9_-]+)", re.IGNORECASE)
CONTRACT_RE = re.compile(
    r"\|\s*`sep-(anarchy|democracy|oligarchy|oneonone|tyranny)`\s*"
    r"\|\s*\[.*?\]\(https://stellar\.expert/explorer/([^/\)]+)/contract/(C[A-Z0-9]+)\)",
    re.IGNORECASE,
)


def normalize_network(raw: str) -> str:
    value = raw.strip().lower().replace("-", "").replace("_", "")
    if value in NETWORKS:
        return NETWORKS[value]
    raise ValueError(f"unknown network: {raw}")


def contract_type(raw: str) -> str:
    value = raw.strip().lower()
    if value.startswith("sep-"):
        value = value[4:]
    if value not in CONTRACT_ORDER:
        raise ValueError(f"unknown contract type: {raw}")
    return value


def fetch_releases(repo: str) -> list[dict[str, Any]]:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    releases: list[dict[str, Any]] = []
    page = 1

    while True:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "onym-contracts-manifest-generator",
            },
        )
        if token:
            request.add_header("Authorization", f"Bearer {token}")

        with urllib.request.urlopen(request, timeout=30) as response:
            batch = json.load(response)

        if not batch:
            break
        releases.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    return releases


def load_releases(args: argparse.Namespace) -> list[dict[str, Any]]:
    if args.input:
        with args.input.open(encoding="utf-8") as handle:
            return json.load(handle)
    return fetch_releases(args.repo)


def release_time(release: dict[str, Any]) -> str:
    return (
        release.get("published_at")
        or release.get("publishedAt")
        or release.get("created_at")
        or release.get("createdAt")
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def release_tag(release: dict[str, Any]) -> str:
    return release.get("tag_name") or release.get("tagName") or release.get("name") or ""


def body_network(body: str) -> str | None:
    match = NETWORK_RE.search(body)
    if not match:
        return None
    return normalize_network(match.group(1))


def contracts_from_body(body: str) -> list[dict[str, str]]:
    default_network = body_network(body)
    contracts: list[dict[str, str]] = []

    for raw_type, raw_network, contract_id in CONTRACT_RE.findall(body):
        network = normalize_network(raw_network)
        if default_network and network != default_network:
            raise ValueError(
                f"release body network {default_network} does not match contract URL network {network}"
            )
        contracts.append(
            {
                "network": network,
                "type": contract_type(raw_type),
                "id": contract_id,
            }
        )

    return sort_contracts(dedupe_contracts(contracts))


def contracts_from_jsonl(path: Path, network: str) -> list[dict[str, str]]:
    contracts: list[dict[str, str]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("row_type") != "contract":
                continue
            contracts.append(
                {
                    "network": network,
                    "type": contract_type(row.get("contract", "")),
                    "id": row.get("address", ""),
                }
            )

    missing_id = [row for row in contracts if not row["id"].startswith("C")]
    if missing_id:
        raise ValueError(f"{path} contains malformed contract rows: {missing_id}")
    if not contracts:
        raise ValueError(f"{path} has no contract rows")

    contracts = sort_contracts(dedupe_contracts(contracts))
    missing_types = sorted(set(CONTRACT_ORDER) - {row["type"] for row in contracts})
    if missing_types:
        raise ValueError(
            f"{path} is missing deployed contract rows for: {', '.join(missing_types)}"
        )

    return contracts


def dedupe_contracts(contracts: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, str]] = []
    for contract in contracts:
        key = (contract["network"], contract["type"], contract["id"])
        if key in seen:
            continue
        seen.add(key)
        result.append(contract)
    return result


def sort_contracts(contracts: list[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(
        contracts,
        key=lambda row: (
            row["network"],
            CONTRACT_ORDER.index(row["type"]) if row["type"] in CONTRACT_ORDER else 99,
            row["id"],
        ),
    )


def release_sort_key(entry: dict[str, Any]) -> tuple[str, str]:
    return (entry["publishedAt"], entry["release"])


def generate_manifest(args: argparse.Namespace) -> dict[str, Any]:
    entries: dict[str, dict[str, Any]] = {}
    releases = load_releases(args)

    for release in releases:
        if release.get("draft"):
            continue
        tag = release_tag(release)
        if not tag:
            continue
        contracts = contracts_from_body(release.get("body") or "")
        if not contracts:
            continue
        entries[tag] = {
            "release": tag,
            "publishedAt": release_time(release),
            "contracts": contracts,
        }

    if args.current_jsonl:
        current_tag = args.current_tag
        current_network = normalize_network(args.current_network)
        published_at = entries.get(current_tag, {}).get("publishedAt")
        if not published_at:
            for release in releases:
                if release_tag(release) == current_tag:
                    published_at = release_time(release)
                    break
        entries[current_tag] = {
            "release": current_tag,
            "publishedAt": published_at
            or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "contracts": contracts_from_jsonl(args.current_jsonl, current_network),
        }

    if not entries:
        raise ValueError("no contract deployments found in release data")

    releases = sorted(entries.values(), key=release_sort_key, reverse=True)
    return {"version": 1, "releases": releases}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", "onymchat/onym-contracts"),
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Read releases JSON from a file instead of GitHub",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--current-tag", default=os.environ.get("GITHUB_REF_NAME", ""))
    parser.add_argument("--current-jsonl", type=Path)
    parser.add_argument("--current-network", default="testnet")
    args = parser.parse_args()

    if args.current_jsonl and not args.current_tag:
        parser.error("--current-tag is required with --current-jsonl")
    return args


def main() -> int:
    args = parse_args()
    manifest = generate_manifest(args)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n")

    counts = {
        release["release"]: len(release["contracts"])
        for release in manifest["releases"]
    }
    print(f"generated contracts manifest: {counts}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
