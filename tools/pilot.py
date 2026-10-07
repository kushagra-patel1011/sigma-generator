"""The validation pilot: the subset of the drawn sample that is run first.

    python -m tools.pilot            # the pilot rules, in run order
    python -m tools.pilot --ids      # comma-separated technique IDs per phase

The rule, fixed in docs/validation/pilot-plan.md: from docs/validation/sample.json,
take the sampled rules (``selected``) with the lowest draw ``rank`` in each tier,
4 per tier. The draw order is already a seeded random order, so the pilot is a
random subset of the sample rather than one biased towards low technique IDs.

Phase 1 runs every pilot rule except the one with the most ART tests; phase 2
runs that rule. The runner resumes where it stopped, so phase 1 can be reviewed
before committing the lab time phase 2 needs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_PATH = ROOT / "docs" / "validation" / "sample.json"
TIERS = ("strong", "moderate", "weak")
PER_TIER = 4


def select(sample: dict[str, Any], per_tier: int = PER_TIER) -> dict[str, list[dict[str, Any]]]:
    """The pilot rules per tier: the ``per_tier`` sampled rules with the lowest draw rank."""
    chosen: dict[str, list[dict[str, Any]]] = {}
    for tier in TIERS:
        sampled = [rule for rule in sample["strata"][tier] if rule["selected"]]
        chosen[tier] = sorted(sampled, key=lambda rule: rule["rank"])[:per_tier]
    return chosen


def phases(chosen: dict[str, list[dict[str, Any]]]) -> tuple[list[str], list[str]]:
    """Technique IDs for phase 1 (all but the largest rule) and phase 2 (the largest)."""
    rules = [rule for tier in TIERS for rule in chosen[tier]]
    largest = max(rules, key=lambda rule: (len(rule["art_tests"]), rule["technique_id"]))
    first = [rule["technique_id"] for rule in rules if rule is not largest]
    return first, [largest["technique_id"]]


def load_sample(path: Path = SAMPLE_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.pilot", description=__doc__.split("\n\n")[0])
    parser.add_argument("--ids", action="store_true", help="print the technique IDs of each phase, comma-separated")
    args = parser.parse_args(argv)

    chosen = select(load_sample())
    first, second = phases(chosen)
    if args.ids:
        print("phase 1:", ",".join(first))
        print("phase 2:", ",".join(second))
        return 0
    total = 0
    for tier in TIERS:
        for rule in chosen[tier]:
            tests = len(rule["art_tests"])
            total += tests
            print(f"{tier:<9} rank {rule['rank']:>2}  {rule['technique_id']:<10} {tests:>3} ART test(s)  "
                  f"{rule['technique_name']}")
    print(f"{total} ART tests; phase 1: {','.join(first)}; phase 2: {','.join(second)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
