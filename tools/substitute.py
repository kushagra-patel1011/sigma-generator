"""Substitution (protocol section 4): replace a sampled rule none of whose ART tests could be executed.

A sampled rule is replaced by the next rule in its tier's queue only when every one of its mapped ART tests
was recorded with its prerequisites failed. This module decides that from the runner's records and keeps the
substitutions in ``<results>/substitutions.json``, which the runner reads to plan the replacement's tests and
``tools/score.py`` reads to score them. The replacement's rule file is the one frozen before any test ran
(``docs/validation/population/``, amendment 4).

    python -m tools.substitute status   # each rule in the current sample: recorded, executed, due or not
    python -m tools.substitute apply    # record every due substitution, then print the runner command

The file is checked whenever it is read: every substitution must name a rule that was in the sample at the
time, and take the next unused rule of the same tier's queue, in draw order. Nothing here edits the sample.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.utils import write_text  # noqa: E402
from tools import population as pop  # noqa: E402

TIERS = ("strong", "moderate", "weak")
FILE_NAME = "substitutions.json"
DEFAULT_RESULTS = ROOT / "output" / "round1"
REASON = "every mapped ART test failed its prerequisites (protocol section 4)"


class SubstitutionError(Exception):
    """The substitution record contradicts the protocol, or a substitution is not due."""


def load_substitutions(results: Path) -> list[dict[str, Any]]:
    path = results / FILE_NAME
    if not path.is_file():
        return []
    return list(json.loads(path.read_text(encoding="utf-8-sig")).get("substitutions") or [])


def queue(sample: dict[str, Any], tier: str) -> list[dict[str, Any]]:
    return sorted((r for r in sample["strata"][tier] if not r.get("selected")), key=lambda r: int(r["rank"]))


def current_sample(sample: dict[str, Any], substitutions: Sequence[dict[str, Any]],
                   population: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """The rules under test per tier after ``substitutions``, each with its ``rule_id`` and ``rule_file``.

    Raises :class:`SubstitutionError` if a substitution replaces a rule that was not in the sample at that
    point, or does not take the next unused rule of its tier's queue."""
    by_technique = pop.rules_by_technique(population)
    current = {tier: [dict(r) for r in sample["strata"][tier] if r.get("selected")] for tier in TIERS}
    used = {tier: 0 for tier in TIERS}
    for number, entry in enumerate(substitutions, 1):
        tier = entry.get("tier")
        if tier not in current:
            raise SubstitutionError(f"substitution {number}: unknown tier {tier!r}")
        replaced = entry["replaced"]["technique_id"]
        position = next((i for i, r in enumerate(current[tier]) if r["technique_id"] == replaced), None)
        if position is None:
            raise SubstitutionError(f"substitution {number}: {replaced} is not in the {tier} sample at that point")
        waiting = queue(sample, tier)
        if used[tier] >= len(waiting):
            raise SubstitutionError(f"substitution {number}: the {tier} queue is exhausted")
        expected = waiting[used[tier]]
        if entry["replacement"]["technique_id"] != expected["technique_id"]:
            raise SubstitutionError(f"substitution {number}: the next {tier} rule in the queue is "
                                    f"{expected['technique_id']}, not {entry['replacement']['technique_id']}")
        frozen = by_technique[expected["technique_id"]]
        if entry["replacement"].get("rule_id") != frozen["rule_id"]:
            raise SubstitutionError(f"substitution {number}: {expected['technique_id']} has rule id "
                                    f"{frozen['rule_id']} in the frozen population")
        used[tier] += 1
        current[tier][position] = dict(expected, rule_id=frozen["rule_id"],
                                       rule_file=f"population/{frozen['rule_file']}", replaces=replaced)
    return current


def _records_by_rule(results: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    from tools import score

    records, harness_errors = score.load_records(results)
    by_rule: dict[str, list[dict[str, Any]]] = {}
    for _, record in records:
        by_rule.setdefault(str(record.get("rule_id", "")), []).append(record)
    return by_rule, harness_errors


def status(sample: dict[str, Any], substitutions: Sequence[dict[str, Any]], population: dict[str, Any],
           results: Path) -> list[dict[str, Any]]:
    """One row per rule in the current sample: what is recorded, and whether a substitution is due."""
    by_rule, harness_errors = _records_by_rule(results)
    rows = []
    for tier, rules in current_sample(sample, substitutions, population).items():
        for rule in rules:
            records = by_rule.get(rule["rule_id"], [])
            mapped = {test["guid"] for test in rule["art_tests"]}
            recorded = {str(r.get("test_guid")) for r in records} & mapped
            failed = [r for r in records if r.get("prereq_status") != "met" and str(r.get("test_guid")) in mapped]
            due = bool(mapped) and recorded == mapped and len(failed) == len(mapped) \
                and not harness_errors.get(rule["rule_id"])
            rows.append({"tier": tier, "rank": int(rule["rank"]), "technique_id": rule["technique_id"],
                         "rule_id": rule["rule_id"], "rule_file": rule["rule_file"], "mapped": len(mapped),
                         "recorded": len(recorded), "prerequisites_failed": len(failed),
                         "executed": len(recorded) - len(failed), "harness_errors": harness_errors.get(rule["rule_id"], 0),
                         "replaces": rule.get("replaces", ""), "due": due, "failed_records": failed})
    return rows


def apply(sample: dict[str, Any], population: dict[str, Any], results: Path,
          now: Optional[datetime] = None) -> list[dict[str, Any]]:
    """Record every due substitution, repeating until none is due. Returns the new entries."""
    substitutions = load_substitutions(results)
    added: list[dict[str, Any]] = []
    by_technique = pop.rules_by_technique(population)
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    while True:
        due = [row for row in status(sample, substitutions, population, results) if row["due"]]
        if not due:
            break
        row = due[0]
        used = sum(1 for entry in substitutions if entry["tier"] == row["tier"])
        waiting = queue(sample, row["tier"])
        if used >= len(waiting):
            raise SubstitutionError(f"{row['technique_id']} is due for substitution, but the {row['tier']} queue is exhausted")
        nxt = waiting[used]
        frozen = by_technique[nxt["technique_id"]]
        entry = {
            "tier": row["tier"],
            "replaced": {"technique_id": row["technique_id"], "rank": row["rank"], "rule_id": row["rule_id"]},
            "replacement": {"technique_id": nxt["technique_id"], "rank": int(nxt["rank"]),
                            "rule_id": frozen["rule_id"], "rule_file": f"population/{frozen['rule_file']}"},
            "reason": REASON,
            "failed_tests": [{"guid": r.get("test_guid"), "name": r.get("test_name"),
                              "prereq_check_output": r.get("prereq_check_output", "")}
                             for r in row["failed_records"]],
            "recorded_utc": stamp,
        }
        substitutions.append(entry)
        current_sample(sample, substitutions, population)     # re-check before anything is written
        added.append(entry)
    if added:
        document = {"protocol": "docs/validation-protocol.md", "substitutions": substitutions}
        write_text(results / FILE_NAME, json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    return added


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.substitute", description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=["status", "apply"])
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS,
                        help="the runner's results folder (default: output/round1)")
    args = parser.parse_args(argv)
    try:
        sample, population = pop.load_sample(), pop.load_population()
        if args.command == "status":
            rows = status(sample, load_substitutions(args.results), population, args.results)
            print(f"{'tier':<9} {'rank':>4}  {'technique':<11} {'mapped':>6} {'recorded':>8} {'prereq failed':>13} "
                  f"{'executed':>8}  note")
            for row in rows:
                note = "SUBSTITUTION DUE" if row["due"] else (f"replaces {row['replaces']}" if row["replaces"] else "")
                print(f"{row['tier']:<9} {row['rank']:>4}  {row['technique_id']:<11} {row['mapped']:>6} "
                      f"{row['recorded']:>8} {row['prerequisites_failed']:>13} {row['executed']:>8}  {note}")
            return 0
        added = apply(sample, population, args.results)
        if not added:
            print("No substitution is due.")
            return 0
        for entry in added:
            print(f"{entry['tier']}: {entry['replaced']['technique_id']} replaced by "
                  f"{entry['replacement']['technique_id']} (queue rank {entry['replacement']['rank']})")
        techniques = ",".join(f"'{e['replacement']['technique_id']}'" for e in added)
        print(f"Recorded in {args.results / FILE_NAME}. Run the replacement(s):")
        print(f"  .\\tools\\lab\\Invoke-Round1.ps1 -Hypervisor VirtualBox -Execute -Credential $cred -Technique {techniques}")
        return 0
    except (SubstitutionError, pop.PopulationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
