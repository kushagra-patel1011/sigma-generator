"""Validation harness, step 1: draw the rule sample the protocol fixes.

docs/validation-protocol.md defines the population, eligibility, seed and draw.
This module is that definition in code, committed together with the protocol so
neither can be adjusted after the seed exists.

    python -m tools.validation fetch   # the pinned Atomic Red Team index (~7 MB)
    python -m tools.validation draw    # writes docs/validation/sample.{json,md} and the sampled rules

The seed is the hash of the commit that added docs/validation-protocol.md, so
it is unknown until the protocol is committed and cannot be chosen.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from src.utils import write_text  # noqa: E402
from tools import corpus  # noqa: E402

PROTOCOL = "docs/validation-protocol.md"
OUTPUT_DIR = ROOT / "docs" / "validation"

#: Atomic Red Team, pinned by commit; the index file is also pinned by content.
ART = {
    "commit": "388942adbd9641f4dfdcf079d7efe9a75ec0ac43",
    "index_sha256": "08f8bd071d96261e12e520a8bba4ef85df33e611491f2435671d4f8fe94c49a4",
}
ART["index_url"] = (f"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{ART['commit']}"
                    "/atomics/Indexes/index.yaml")
ART_INDEX_PATH = ROOT / "data" / "validation" / f"art-index-{ART['commit']}.yaml"

PLATFORM = "windows"
#: Rules per tier (protocol section 4).
QUOTA = {"strong": 17, "moderate": 17, "weak": 16}
#: Logsources the lab records (protocol section 6): every Sysmon event the
#: pinned config can emit, plus the Security, System and PowerShell channels.
LAB_LOGSOURCES = frozenset({
    "category:process_creation", "category:network_connection", "category:file_event", "category:file_delete",
    "category:file_change", "category:process_access", "category:image_load", "category:driver_load",
    "category:create_remote_thread", "category:create_stream_hash", "category:raw_access_thread",
    "category:registry_add", "category:registry_delete", "category:registry_set", "category:registry_rename",
    "category:registry_event", "category:pipe_created", "category:wmi_event", "category:dns_query",
    "category:process_termination", "category:process_tampering", "category:ps_script", "category:ps_module",
    "service:security", "service:system", "service:powershell",
})


class ValidationError(Exception):
    """A pin, the protocol commit or the corpus does not match what the protocol fixes."""


# --------------------------------------------------------------------------- #
# Atomic Red Team
# --------------------------------------------------------------------------- #
def fetch_art_index(path: Path = ART_INDEX_PATH, timeout: int = 180) -> Path:
    if path.is_file() and corpus.sha256_of(path) == ART["index_sha256"]:
        return path
    import requests

    response = requests.get(ART["index_url"], timeout=timeout)
    response.raise_for_status()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(response.content)
    actual = corpus.sha256_of(path)
    if actual != ART["index_sha256"]:
        raise ValidationError(f"{ART['index_url']} has sha256 {actual}, expected {ART['index_sha256']}")
    return path


def load_art_index(path: Path = ART_INDEX_PATH) -> dict[str, Any]:
    if not path.is_file():
        raise ValidationError(f"{path.relative_to(ROOT)} is missing. Run: python -m tools.validation fetch")
    if corpus.sha256_of(path) != ART["index_sha256"]:
        raise ValidationError(f"{path.relative_to(ROOT)} is not the pinned ART index. Run: python -m tools.validation fetch")
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    with path.open(encoding="utf-8") as handle:
        return yaml.load(handle, Loader=loader)


def art_tests_by_technique(index: dict[str, Any], platform: str = PLATFORM) -> dict[str, list[dict[str, Any]]]:
    """Automated ART tests per technique ID that support ``platform``.

    The index files a technique under each of its tactics, so tests are
    de-duplicated by GUID, keeping the index's own order.  Tests whose executor
    is ``manual`` cannot be run by the harness and are left out."""
    tests: dict[str, list[dict[str, Any]]] = {}
    seen: set[str] = set()
    for techniques in index.values():
        for technique_id, body in (techniques or {}).items():
            for test in (body or {}).get("atomic_tests") or []:
                guid = test.get("auto_generated_guid")
                executor = test.get("executor") or {}
                platforms = [str(p).lower() for p in test.get("supported_platforms") or []]
                if not guid or guid in seen or platform not in platforms or executor.get("name") == "manual":
                    continue
                seen.add(guid)
                tests.setdefault(technique_id, []).append({
                    "guid": guid,
                    "name": test.get("name", ""),
                    "executor": executor.get("name", ""),
                    "elevation_required": bool(executor.get("elevation_required", False)),
                })
    return tests


# --------------------------------------------------------------------------- #
# Population, eligibility and draw
# --------------------------------------------------------------------------- #
def logsource_key(logsource: dict[str, str]) -> str:
    if logsource.get("category"):
        return f"category:{logsource['category']}"
    return f"service:{logsource.get('service', '')}"


def population(digest: dict[str, Any], platform: str = PLATFORM) -> list[dict[str, Any]]:
    """The default rule of every technique whose rule targets ``platform``."""
    rules = []
    for technique_id, entry in sorted(digest["techniques"].items()):
        if entry["rules"] and entry["rules"][0]["logsource"].get("product") == platform:
            rule = entry["rules"][0]
            rules.append({
                "technique_id": technique_id,
                "technique_name": entry["name"],
                "tier": rule["tier"],
                "analytic": rule["analytic"],
                "logsource": logsource_key(rule["logsource"]),
                "level": rule["level"],
            })
    return rules


def eligible(rules: Iterable[dict[str, Any]], tests: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Rules whose logsource the lab records and whose exact technique ID has at
    least one automated ART test for the platform (no parent/sub-technique borrowing)."""
    return [dict(rule, art_tests=tests[rule["technique_id"]]) for rule in rules
            if rule["logsource"] in LAB_LOGSOURCES and tests.get(rule["technique_id"])]


def order_key(seed: str, technique_id: str) -> str:
    return hashlib.sha256(f"{seed}:{technique_id}".encode("utf-8")).hexdigest()


def draw(candidates: Iterable[dict[str, Any]], seed: str, quota: dict[str, int] = QUOTA) -> dict[str, list[dict[str, Any]]]:
    """Every eligible rule per tier in draw order; the first ``quota[tier]`` are
    the sample and the rest, in order, are the substitution queue."""
    strata: dict[str, list[dict[str, Any]]] = {tier: [] for tier in quota}
    for rule in candidates:
        if rule["tier"] in strata:
            strata[rule["tier"]].append(dict(rule, order_key=order_key(seed, rule["technique_id"])))
    for tier, rules in strata.items():
        rules.sort(key=lambda r: (r["order_key"], r["technique_id"]))
        for rank, rule in enumerate(rules, 1):
            rule["rank"] = rank
            rule["selected"] = rank <= quota[tier]
    return strata


def protocol_seed(root: Path = ROOT, protocol: str = PROTOCOL) -> str:
    """Hash of the commit that first added the protocol document."""
    try:
        out = subprocess.run(
            ["git", "log", "--diff-filter=A", "--format=%H", "--", protocol],
            cwd=str(root), check=True, capture_output=True, text=True,
        ).stdout.split()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValidationError(f"could not read git history: {exc}") from exc
    if not out:
        raise ValidationError(f"{protocol} is not committed yet; the seed is the hash of the commit that adds it")
    return out[-1]


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def run_draw(output_dir: Path = OUTPUT_DIR) -> dict[str, Any]:
    seed = protocol_seed()
    dataset = corpus.load_pinned_dataset()
    digest = corpus.build_digest(dataset, source_sha256=corpus.PINNED_ATTACK["sha256"])
    drift = corpus.compare(corpus.load_baseline(), digest)
    if drift:
        raise ValidationError("the generator no longer matches tests/corpus/baseline.json; "
                              "the sample must be drawn from the baselined corpus:\n" + "\n".join(drift[:20]))

    rules = population(digest)
    tests = art_tests_by_technique(load_art_index())
    strata = draw(eligible(rules, tests), seed)

    from src.sigma_generator import SigmaRuleGenerator

    generator = SigmaRuleGenerator(deterministic=True, attack_version=dataset.version)
    rules_dir = output_dir / "rules"
    for tier_rules in strata.values():
        for rule in tier_rules:
            if not rule["selected"]:
                continue
            sigma = generator.generate(dataset.get_technique(rule["technique_id"]))[0]
            if (sigma.provenance.analytic_id, sigma.quality.tier) != (rule["analytic"], rule["tier"]):
                raise ValidationError(f"{rule['technique_id']}: generated rule does not match the baseline")
            rule["rule_id"] = sigma.id
            rule["rule_file"] = f"rules/{sigma.filename()}"
            write_text(rules_dir / sigma.filename(), sigma.to_yaml())

    totals = {tier: sum(1 for r in rules if r["tier"] == tier) for tier in QUOTA}
    sample = {
        "protocol": PROTOCOL,
        "seed": seed,
        "attack": digest["attack"],
        "art": {"commit": ART["commit"], "index_sha256": ART["index_sha256"]},
        "platform": PLATFORM,
        "quota": QUOTA,
        "population": {tier: {"default_rules": totals[tier], "eligible": len(strata[tier])} for tier in QUOTA},
        "strata": strata,
    }
    write_text(output_dir / "sample.json", json.dumps(sample, indent=1, ensure_ascii=False) + "\n")
    write_text(output_dir / "sample.md", render_markdown(sample))
    return sample


def render_markdown(sample: dict[str, Any]) -> str:
    lines = [
        "# Validation sample (round 1, Windows)",
        "",
        f"Drawn by `python -m tools.validation draw` under [the protocol](../validation-protocol.md).",
        "",
        f"- Seed: `{sample['seed']}` (the commit that added the protocol)",
        f"- ATT&CK {sample['attack']['version']}, sha256 `{sample['attack']['sha256'][:16]}...`",
        f"- Atomic Red Team commit `{sample['art']['commit']}`",
        "",
        "| Tier | Windows default rules | Eligible | Drawn |",
        "|---|---|---|---|",
    ]
    for tier, counts in sample["population"].items():
        lines.append(f"| {tier} | {counts['default_rules']} | {counts['eligible']} | {sample['quota'][tier]} |")
    for tier, rules in sample["strata"].items():
        selected = [r for r in rules if r["selected"]]
        lines += [
            "",
            f"## {tier.capitalize()} ({len(selected)} rules, {sum(len(r['art_tests']) for r in selected)} ART tests)",
            "",
            "| # | Technique | Logsource | Analytic | ART tests | Rule |",
            "|---|---|---|---|---|---|",
        ]
        for rule in selected:
            lines.append(
                f"| {rule['rank']} | {rule['technique_id']} {rule['technique_name']} | {rule['logsource']} | "
                f"{rule['analytic']} | {len(rule['art_tests'])} | [{rule['rule_id'][:8]}]({rule['rule_file']}) |"
            )
        queue = [r["technique_id"] for r in rules if not r["selected"]]
        lines += ["", f"Substitution queue, in order: {', '.join(queue) if queue else '(empty)'}"]
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.validation", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("fetch", help="download the pinned Atomic Red Team index")
    sub.add_parser("draw", help="draw the sample from the seed and write docs/validation/")
    args = parser.parse_args(argv)
    logging.getLogger("sigma_generator").setLevel(logging.WARNING)
    try:
        if args.command == "fetch":
            print(f"ART index at {fetch_art_index().relative_to(ROOT)}")
            return 0
        sample = run_draw()
        print(f"Seed {sample['seed']}")
        for tier, counts in sample["population"].items():
            print(f"  {tier:<9} {counts['default_rules']:>4} Windows default rules, {counts['eligible']:>4} eligible, "
                  f"{sample['quota'][tier]} drawn")
        print(f"Wrote {OUTPUT_DIR.relative_to(ROOT)}/sample.json, sample.md and rules/")
        return 0
    except (ValidationError, corpus.CorpusError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
