"""Corpus snapshot: pin down what the generator produces for every technique.

The unit suite checks behaviours one at a time against small synthetic
analytics.  This checks the whole corpus at once: every active technique in a
pinned ATT&CK release is generated (every analytic's rule, attack chain and
count rule) and reduced to a digest of what matters for detection - quality
tier, level, logsource, selection fields and values, condition, correlation
type, threshold, time window and group-by.  Titles, descriptions, dates and
UUIDs are left out, so the digest only changes when detection content does.

    python -m tools.corpus fetch    # download the pinned ATT&CK bundle (~55 MB)
    python -m tools.corpus check    # compare the current output with the baseline
    python -m tools.corpus bless    # show the drift, then accept it as the new baseline

The baseline is committed at tests/corpus/baseline.json.  Re-bless only when a
change to generated content is intended, and commit the baseline with it so
the drift is reviewed alongside the code that caused it.

Moving to a newer ATT&CK release: update ``PINNED_ATTACK`` below, ``fetch``,
then ``bless``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src import __version__  # noqa: E402
from src.attack_fetcher import AttackDataset, download_bundle  # noqa: E402
from src.sigma_generator import ChainRule, SigmaRule, SigmaRuleGenerator  # noqa: E402
from src.utils import InsufficientEvidenceError, SigmaGeneratorError, UnmappableTechniqueError  # noqa: E402

#: The ATT&CK release the baseline is generated from.  Pinned by content hash,
#: so a MITRE release can never move the baseline on its own.
PINNED_ATTACK = {
    "version": "19.2",
    "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
           "enterprise-attack/enterprise-attack-19.2.json",
    "sha256": "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4",
}
BUNDLE_PATH = ROOT / "data" / "corpus" / f"enterprise-attack-{PINNED_ATTACK['version']}.json"
BASELINE_PATH = ROOT / "tests" / "corpus" / "baseline.json"
#: Bump when the digest's shape changes, so an old baseline is refused rather
#: than reported as thousands of spurious differences.
SCHEMA = 1


class CorpusError(Exception):
    """The pinned bundle or the baseline is missing or does not match."""


# --------------------------------------------------------------------------- #
# Pinned bundle
# --------------------------------------------------------------------------- #
def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_bundle(path: Path = BUNDLE_PATH, timeout: int = 180) -> Path:
    """Download the pinned bundle unless an identical copy is already there."""
    if path.is_file() and sha256_of(path) == PINNED_ATTACK["sha256"]:
        return path
    download_bundle(path, url=PINNED_ATTACK["url"], timeout=timeout)
    actual = sha256_of(path)
    if actual != PINNED_ATTACK["sha256"]:
        raise CorpusError(
            f"{PINNED_ATTACK['url']} has sha256 {actual}, expected {PINNED_ATTACK['sha256']}. "
            "The published file changed; pin a release deliberately rather than accepting it."
        )
    return path


def load_pinned_dataset(path: Path = BUNDLE_PATH) -> AttackDataset:
    if not path.is_file():
        raise CorpusError(f"{_relative(path)} is missing. Run: python -m tools.corpus fetch")
    actual = sha256_of(path)
    if actual != PINNED_ATTACK["sha256"]:
        raise CorpusError(
            f"{_relative(path)} is not ATT&CK {PINNED_ATTACK['version']} as pinned "
            f"(sha256 {actual[:12]}..., expected {PINNED_ATTACK['sha256'][:12]}...). "
            "Run: python -m tools.corpus fetch"
        )
    return AttackDataset.from_file(path)


# --------------------------------------------------------------------------- #
# Digest
# --------------------------------------------------------------------------- #
def build_digest(dataset: AttackDataset, technique_ids: Optional[Iterable[str]] = None,
                 source_sha256: str = "") -> dict[str, Any]:
    """Digest of everything the generator produces for ``technique_ids``
    (default: every technique that is neither revoked nor deprecated).
    ``source_sha256`` records which bundle file the digest came from."""
    generator = SigmaRuleGenerator(deterministic=True, attack_version=dataset.version)
    if technique_ids is None:
        technique_ids = [
            tid for tid in dataset.technique_ids()
            if not (dataset.get_technique(tid).revoked or dataset.get_technique(tid).deprecated)
        ]
    techniques: dict[str, Any] = {}
    for technique_id in sorted(technique_ids):
        technique = dataset.get_technique(technique_id)
        entry: dict[str, Any] = {"name": technique.name, "status": "generated", "rules": [], "correlations": []}
        try:
            # Every analytic's rule, best first: the first is what `generate` writes by default.
            entry["rules"] = [digest_rule(rule) for rule in generator.generate(technique, all_analytics=True)]
        except InsufficientEvidenceError:
            entry["status"] = "insufficient"
        except UnmappableTechniqueError:
            entry["status"] = "unmappable"
        if entry["status"] != "unmappable":
            entry["correlations"] = [
                digest_correlation(chain) for chain in generator.generate_correlations(technique, all_analytics=True)
            ]
        techniques[technique.id] = entry
    return {
        "schema": SCHEMA,
        "attack": {"version": dataset.version, "sha256": source_sha256},
        "summary": summarise(techniques),
        "techniques": techniques,
    }


def digest_rule(rule: SigmaRule) -> dict[str, Any]:
    return {
        "analytic": rule.provenance.analytic_id,
        "logsource": dict(sorted(rule.logsource.items())),
        "confidence": round(rule.provenance.confidence, 2),
        "tier": rule.quality.tier,
        "signals": rule.quality.signals,
        "level": rule.level,
        "detection": normalise_detection(rule.detection),
    }


def digest_correlation(chain: ChainRule) -> dict[str, Any]:
    correlation = chain.correlation
    digest: dict[str, Any] = {
        "kind": chain.kind,
        "analytic": chain.provenance.analytic_id,
        "type": correlation.get("type"),
        "tier": chain.quality.tier,
        "level": chain.level,
        "timespan": correlation.get("timespan"),
        "group-by": list(correlation.get("group-by") or []),
    }
    if "condition" in correlation:
        digest["condition"] = correlation["condition"]
    digest["steps"] = [
        {
            "name": step.name,
            "logsource": dict(sorted(step.logsource.items())),
            "tier": step.quality.tier,
            "detection": normalise_detection(step.detection),
        }
        for step in chain.steps
    ]
    return digest


def normalise_detection(detection: dict[str, Any]) -> dict[str, Any]:
    """Selections as ``{name: {field: sorted values}}`` plus the condition.

    A list of values is a set of alternatives, so its order carries no meaning
    and is sorted away."""
    out: dict[str, Any] = {}
    for name in sorted(detection):
        block = detection[name]
        out[name] = block if name == "condition" else _normalise_block(block)
    return out


def _normalise_block(block: Any) -> Any:
    if isinstance(block, dict):
        return {field: _values(value) for field, value in sorted(block.items())}
    if isinstance(block, list):
        if all(isinstance(item, dict) for item in block):
            return [_normalise_block(item) for item in block]
        return _values(block)
    return block


def _values(value: Any) -> list[Any]:
    values = value if isinstance(value, list) else [value]
    return sorted(values, key=lambda v: (type(v).__name__, str(v)))


def summarise(techniques: dict[str, Any]) -> dict[str, Any]:
    status = Counter(entry["status"] for entry in techniques.values())
    primary = Counter(entry["rules"][0]["tier"] for entry in techniques.values() if entry["rules"])
    rules = Counter(rule["tier"] for entry in techniques.values() for rule in entry["rules"])
    correlations = Counter(
        f"{c['type']}/{c['tier']}" for entry in techniques.values() for c in entry["correlations"]
    )
    return {
        "techniques": len(techniques),
        "status": dict(sorted(status.items())),
        "default_rule_tiers": dict(sorted(primary.items())),
        "all_rule_tiers": dict(sorted(rules.items())),
        "correlations": dict(sorted(correlations.items())),
    }


def dump_digest(digest: dict[str, Any]) -> str:
    return json.dumps(digest, indent=1, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #
def compare(baseline: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """A readable account of how ``current`` differs from ``baseline``; empty if identical."""
    if baseline.get("schema") != current.get("schema"):
        return [f"Baseline digest schema {baseline.get('schema')} != current schema {current.get('schema')}: re-bless."]
    if baseline.get("attack") != current.get("attack"):
        return [f"Baseline was blessed against ATT&CK {baseline.get('attack')}, the pin is now "
                f"{current.get('attack')}: re-bless to accept the new release's drift."]

    old, new = baseline["techniques"], current["techniques"]
    tally: Counter = Counter()
    details: list[str] = []
    for technique_id in sorted(set(old) | set(new)):
        if technique_id not in new:
            details += [f"{technique_id} {old[technique_id]['name']}", "  technique no longer generated"]
            tally["removed"] += 1
            continue
        if technique_id not in old:
            details += [f"{technique_id} {new[technique_id]['name']}", "  technique is new"]
            tally["added"] += 1
            continue
        lines = _compare_technique(old[technique_id], new[technique_id], tally)
        if lines:
            tally["changed"] += 1
            details += [f"{technique_id} {new[technique_id]['name']}"] + ["  " + line for line in lines]
    if not details:
        return []

    header = [
        f"Corpus drift against the baseline (ATT&CK {current['attack']['version']}, "
        f"{len(new)} techniques)",
        f"  {tally['changed']} technique(s) changed, {tally['added']} added, {tally['removed']} removed",
    ]
    for label, prefix in (("rule tiers", "rule-tier "), ("default-rule tiers", "primary-tier "),
                          ("correlation tiers", "corr-tier ")):
        moves = sorted((key[len(prefix):], count) for key, count in tally.items()
                       if isinstance(key, str) and key.startswith(prefix))
        if moves:
            header.append(f"  {label + ':':<20}" + ", ".join(f"{move} x{count}" for move, count in moves))
    if tally["gained"] or tally["lost"]:
        header.append(f"  {'values:':<20}+{tally['gained']} gained, -{tally['lost']} lost")
    for key, label in (("rules+", "rules added"), ("rules-", "rules removed"),
                       ("corr+", "correlations added"), ("corr-", "correlations removed")):
        if tally[key]:
            header.append(f"  {label + ':':<20}{tally[key]}")
    return header + [""] + details


def _compare_technique(old: dict[str, Any], new: dict[str, Any], tally: Counter) -> list[str]:
    lines: list[str] = []
    if old["status"] != new["status"]:
        lines.append(f"status {old['status']} -> {new['status']}")
    old_primary = _rule_key(old["rules"][0]) if old["rules"] else None
    new_primary = _rule_key(new["rules"][0]) if new["rules"] else None
    if old_primary != new_primary:
        lines.append(f"default rule {_label(old_primary)} -> {_label(new_primary)}")
    if old["rules"] and new["rules"] and old["rules"][0]["tier"] != new["rules"][0]["tier"]:
        tally[f"primary-tier {old['rules'][0]['tier']} -> {new['rules'][0]['tier']}"] += 1

    old_rules = _keyed(old["rules"], _rule_key)
    new_rules = _keyed(new["rules"], _rule_key)
    for key in _ordered_union(old_rules, new_rules):
        name = f"rule {_label(key)}"
        if key not in new_rules:
            lines.append(f"{name}: removed ({old_rules[key]['tier']})")
            tally["rules-"] += 1
        elif key not in old_rules:
            lines.append(f"{name}: added ({new_rules[key]['tier']})")
            tally["rules+"] += 1
        else:
            before, after = old_rules[key], new_rules[key]
            if before["tier"] != after["tier"]:
                tally[f"rule-tier {before['tier']} -> {after['tier']}"] += 1
            lines += _scalar_changes(name, before, after, ("tier", "signals", "level", "confidence"))
            lines += _detection_changes(name, before["detection"], after["detection"], tally)

    old_corr = _keyed(old["correlations"], _correlation_key)
    new_corr = _keyed(new["correlations"], _correlation_key)
    for key in _ordered_union(old_corr, new_corr):
        name = f"{key[0]} {key[1] or '-'}"
        if key not in new_corr:
            lines.append(f"{name}: removed ({old_corr[key]['type']}, {old_corr[key]['tier']})")
            tally["corr-"] += 1
        elif key not in old_corr:
            lines.append(f"{name}: added ({new_corr[key]['type']}, {new_corr[key]['tier']})")
            tally["corr+"] += 1
        else:
            before, after = old_corr[key], new_corr[key]
            if before["tier"] != after["tier"]:
                tally[f"corr-tier {before['tier']} -> {after['tier']}"] += 1
            lines += _scalar_changes(name, before, after,
                                     ("type", "tier", "level", "timespan", "group-by", "condition"))
            old_steps = {step["name"]: step for step in before["steps"]}
            new_steps = {step["name"]: step for step in after["steps"]}
            for step_name in _ordered_union(old_steps, new_steps):
                label = f"{name} {step_name}"
                if step_name not in new_steps:
                    lines.append(f"{label}: step removed")
                elif step_name not in old_steps:
                    lines.append(f"{label}: step added ({new_steps[step_name]['tier']})")
                else:
                    lines += _scalar_changes(label, old_steps[step_name], new_steps[step_name], ("logsource", "tier"))
                    lines += _detection_changes(label, old_steps[step_name]["detection"],
                                                new_steps[step_name]["detection"], tally)
    return lines


def _rule_key(rule: dict[str, Any]) -> tuple[str, str]:
    return rule["analytic"] or "-", "/".join(f"{k}={v}" for k, v in sorted(rule["logsource"].items()))


def _correlation_key(correlation: dict[str, Any]) -> tuple[str, str]:
    return correlation["kind"], correlation["analytic"] or "-"


def _label(key: Optional[tuple[str, str]]) -> str:
    return f"{key[0]} [{key[1]}]" if key else "(none)"


def _keyed(items: list[dict[str, Any]], key_of) -> dict[Any, dict[str, Any]]:
    """Index by key, keeping order; a repeated key gets a counter so nothing is dropped."""
    keyed: dict[Any, dict[str, Any]] = {}
    for item in items:
        key = key_of(item)
        if key in keyed:
            n = 2
            while key + (f"#{n}",) in keyed:
                n += 1
            key = key + (f"#{n}",)
        keyed[key] = item
    return keyed


def _ordered_union(first: dict[Any, Any], second: dict[Any, Any]) -> list[Any]:
    return list(first) + [key for key in second if key not in first]


def _scalar_changes(name: str, before: dict[str, Any], after: dict[str, Any], keys: Sequence[str]) -> list[str]:
    return [f"{name}: {key} {_fmt(before.get(key))} -> {_fmt(after.get(key))}"
            for key in keys if before.get(key) != after.get(key)]


def _detection_changes(name: str, before: dict[str, Any], after: dict[str, Any], tally: Counter) -> list[str]:
    lines: list[str] = []
    for selection in _ordered_union(before, after):
        if selection == "condition":
            if before.get("condition") != after.get("condition"):
                lines.append(f"{name}: condition {_fmt(before.get('condition'))} -> {_fmt(after.get('condition'))}")
            continue
        old_fields = _as_fields(before.get(selection))
        new_fields = _as_fields(after.get(selection))
        if selection not in after:
            lines.append(f"{name}: {selection} removed")
        elif selection not in before:
            lines.append(f"{name}: {selection} added")
        for field in _ordered_union(old_fields, new_fields):
            old_values = old_fields.get(field, [])
            new_values = new_fields.get(field, [])
            lost = [v for v in old_values if v not in new_values]
            gained = [v for v in new_values if v not in old_values]
            tally["lost"] += len(lost)
            tally["gained"] += len(gained)
            if lost:
                lines.append(f"{name}: {selection} {field} lost {_fmt(lost)}")
            if gained:
                lines.append(f"{name}: {selection} {field} gained {_fmt(gained)}")
    return lines


def _as_fields(block: Any) -> dict[str, list[Any]]:
    if block is None:
        return {}
    if isinstance(block, dict):
        return block
    if isinstance(block, list) and all(isinstance(item, dict) for item in block):
        merged: dict[str, list[Any]] = {}
        for index, item in enumerate(block):
            for field, values in item.items():
                merged[f"[{index}] {field}"] = values
        return merged
    return {"(keywords)": block}


def _fmt(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 160 else text[:157] + "..."


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #
def load_baseline(path: Path = BASELINE_PATH) -> dict[str, Any]:
    if not path.is_file():
        raise CorpusError(f"{_relative(path)} is missing. Run: python -m tools.corpus bless")
    return json.loads(path.read_text(encoding="utf-8"))


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.corpus", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("fetch", help=f"download the pinned ATT&CK {PINNED_ATTACK['version']} bundle")
    check = sub.add_parser("check", help="compare the current output with the baseline (exit 1 on drift)")
    check.add_argument("--limit", type=int, default=0, metavar="N", help="print at most N detail lines")
    bless = sub.add_parser("bless", help="print the drift, then write the current output as the baseline")
    bless.add_argument("--quiet", action="store_true", help="do not print the drift")
    args = parser.parse_args(argv)
    logging.getLogger("sigma_generator").setLevel(logging.WARNING)

    try:
        if args.command == "fetch":
            print(f"ATT&CK {PINNED_ATTACK['version']} at {_relative(fetch_bundle())}")
            return 0
        current = build_digest(load_pinned_dataset(), source_sha256=PINNED_ATTACK["sha256"])
        if args.command == "check":
            drift = compare(load_baseline(), current)
            if not drift:
                print(f"No drift: {current['summary']['techniques']} techniques match the baseline.")
                return 0
            shown = drift if not args.limit or len(drift) <= args.limit else (
                drift[:args.limit] + [f"... {len(drift) - args.limit} more line(s)"])
            print("\n".join(shown))
            print("\nIf this change is intended: python -m tools.corpus bless")
            return 1
        # bless
        drift = compare(load_baseline(), current) if BASELINE_PATH.is_file() else ["No previous baseline."]
        if not args.quiet:
            print("\n".join(drift) if drift else "No drift; baseline rewritten unchanged.")
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with BASELINE_PATH.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(dump_digest(current))
        print(f"\nWrote {_relative(BASELINE_PATH)}: {json.dumps(current['summary'])}")
        return 0
    except CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
