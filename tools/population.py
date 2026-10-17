"""Validation population: every rule round 1 converts, frozen before any ART test or benign log.

docs/validation-protocol.md fixes the rules under test as what sigma-generator wrote at the commit that added
the protocol, with ``--deterministic`` and default options (section 2). The draw froze the 50 sampled rules in
``docs/validation/rules/``. Amendment 4 freezes the rest of what round 1 converts, the same way:

* every Windows default rule of section 3 (322). They are the false-positive population of section 10, and
  every rule in a substitution queue (section 4) is one of them;
* every Windows default correlation rule of section 10 (54 ``temporal``, 28 ``event_count``, 9 ``value_count``).

    python -m tools.population freeze   # generate them with the protocol commit's own code, once
    python -m tools.population check    # regenerate and compare with the frozen files

Both need the git history (the protocol commit) and the pinned ATT&CK bundle (``python -m tools.corpus fetch``).
The generator runs from a git worktree of the protocol commit, never from the working tree, so later changes
to the generator cannot reach the rules under test. ``date`` fields are set to the draw date, so the 50 sampled
rules come out byte for byte as the draw wrote them, and ``freeze`` refuses to write anything unless they do.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.utils import write_text  # noqa: E402
from tools import corpus  # noqa: E402

VALIDATION_DIR = ROOT / "docs" / "validation"
SAMPLE_PATH = VALIDATION_DIR / "sample.json"
POPULATION_DIR = VALIDATION_DIR / "population"
MANIFEST_NAME = "population.json"

#: The date the draw wrote into the 50 sampled rules (``date:`` and the banner); every frozen rule carries it.
DRAW_DATE = "2026-09-24"
#: Windows default correlation rules at the protocol commit, by type (protocol section 10).
EXPECTED_CORRELATIONS = {"temporal": 54, "event_count": 28, "value_count": 9}

#: Runs inside a worktree of the protocol commit, with that commit's code only. It writes the rule files under
#: ``out`` and prints what it wrote as JSON. It uses only APIs that exist at the protocol commit.
_GENERATE = r'''
import json, logging, sys
from pathlib import Path

tree, out, bundle, date = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
sys.path.insert(0, str(tree))
import src.sigma_generator as sg
sg.today_iso = lambda: date
from src.sigma_generator import SigmaRuleGenerator
from src.utils import InsufficientEvidenceError, UnmappableTechniqueError, write_text
from tools import corpus

logging.getLogger("sigma_generator").setLevel(logging.ERROR)


def key(logsource):
    if logsource.get("category"):
        return "category:" + logsource["category"]
    return "service:" + logsource.get("service", "")


dataset = corpus.load_pinned_dataset(bundle)
generator = SigmaRuleGenerator(deterministic=True, attack_version=dataset.version)
active = sorted(t for t in dataset.technique_ids()
                if not (dataset.get_technique(t).revoked or dataset.get_technique(t).deprecated))
rules, correlations = [], []
for technique_id in active:
    technique = dataset.get_technique(technique_id)
    try:
        rule = generator.generate(technique)[0]
    except InsufficientEvidenceError:
        rule = None
    except UnmappableTechniqueError:
        continue
    if rule is not None and rule.logsource.get("product") == "windows":
        write_text(out / "rules" / rule.filename(), rule.to_yaml())
        rules.append({"technique_id": technique.id, "technique_name": technique.name, "tier": rule.quality.tier,
                      "analytic": rule.provenance.analytic_id, "logsource": key(rule.logsource),
                      "level": rule.level, "rule_id": rule.id, "rule_file": "rules/" + rule.filename()})
    for chain in generator.generate_correlations(technique):
        if all(step.logsource.get("product") == "windows" for step in chain.steps):
            write_text(out / "correlations" / chain.filename(), chain.to_yaml())
            correlations.append({"technique_id": technique.id, "technique_name": technique.name,
                                 "kind": chain.kind, "type": chain.correlation["type"],
                                 "analytic": chain.provenance.analytic_id, "tier": chain.quality.tier,
                                 "level": chain.level, "rule_id": chain.id,
                                 "rule_file": "correlations/" + chain.filename(),
                                 "steps": [key(step.logsource) for step in chain.steps]})
print(json.dumps({"attack_version": dataset.version, "rules": rules, "correlations": correlations}))
'''


class PopulationError(Exception):
    """The protocol commit, the pinned inputs or the frozen files are not what the protocol fixes."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_sample(path: Path = SAMPLE_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_population(directory: Path = POPULATION_DIR) -> dict[str, Any]:
    path = directory / MANIFEST_NAME
    if not path.is_file():
        raise PopulationError(f"{path} is missing; the population is frozen by: python -m tools.population freeze")
    return json.loads(path.read_text(encoding="utf-8"))


def rules_by_technique(population: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["technique_id"]: entry for entry in population["rules"]}


# --------------------------------------------------------------------------- #
# Generation at the protocol commit
# --------------------------------------------------------------------------- #
def _git(*args: str, cwd: Path = ROOT) -> str:
    try:
        return subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or exc
        raise PopulationError(f"git {' '.join(args)} failed: {detail}") from exc


def generate_at(commit: str, out: Path, bundle: Path = corpus.BUNDLE_PATH, date: str = DRAW_DATE) -> dict[str, Any]:
    """Generate the population with ``commit``'s own code into ``out``; returns what was written."""
    if corpus.sha256_of(bundle) != corpus.PINNED_ATTACK["sha256"]:
        raise PopulationError(f"{bundle} is not the pinned ATT&CK bundle. Run: python -m tools.corpus fetch")
    tree = Path(tempfile.mkdtemp(prefix="protocol-tree-"))
    shutil.rmtree(tree)
    _git("worktree", "add", "--detach", str(tree), commit)
    try:
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        done = subprocess.run([sys.executable, "-c", _GENERATE, str(tree), str(out), str(bundle.resolve()), date],
                              cwd=str(tree), env=env, capture_output=True, text=True)
        if done.returncode != 0:
            raise PopulationError(f"generation at {commit[:7]} failed:\n{done.stderr[-2000:]}")
        return json.loads(done.stdout)
    finally:
        _git("worktree", "remove", "--force", str(tree))


def verify_generated(generated: dict[str, Any], out: Path, sample: dict[str, Any],
                     validation_dir: Path = VALIDATION_DIR) -> list[str]:
    """Every way the generated population disagrees with what the protocol and the draw fixed."""
    problems: list[str] = []
    tiers = {tier: sum(1 for r in generated["rules"] if r["tier"] == tier) for tier in sample["quota"]}
    for tier, counts in sample["population"].items():
        if tiers.get(tier) != counts["default_rules"]:
            problems.append(f"{tier}: {tiers.get(tier)} Windows default rules, the protocol counts {counts['default_rules']}")
    types = {kind: sum(1 for c in generated["correlations"] if c["type"] == kind) for kind in EXPECTED_CORRELATIONS}
    if types != EXPECTED_CORRELATIONS:
        problems.append(f"correlation rules by type {types}, the protocol counts {EXPECTED_CORRELATIONS}")

    by_technique = rules_by_technique(generated)
    for tier, rules in sample["strata"].items():
        for rule in rules:
            entry = by_technique.get(rule["technique_id"])
            if entry is None:
                problems.append(f"{rule['technique_id']}: drawn rule missing from the population")
                continue
            for field in ("tier", "analytic", "logsource", "level"):
                if entry[field] != rule[field]:
                    problems.append(f"{rule['technique_id']}: {field} {entry[field]!r}, sample.json has {rule[field]!r}")
            if rule.get("selected"):
                if entry["rule_id"] != rule["rule_id"]:
                    problems.append(f"{rule['technique_id']}: rule id {entry['rule_id']}, sample.json has {rule['rule_id']}")
                frozen = (validation_dir / rule["rule_file"]).read_bytes()
                if (out / entry["rule_file"]).read_bytes() != frozen:
                    problems.append(f"{rule['technique_id']}: not byte-identical to {rule['rule_file']}")
    return problems


def manifest_for(generated: dict[str, Any], out: Path, sample: dict[str, Any], commit: str) -> dict[str, Any]:
    selected = {r["technique_id"] for rules in sample["strata"].values() for r in rules if r.get("selected")}
    queued = {r["technique_id"] for rules in sample["strata"].values() for r in rules if not r.get("selected")}
    rules = []
    for entry in generated["rules"]:
        status = ("sampled" if entry["technique_id"] in selected
                  else "queued" if entry["technique_id"] in queued else "population")
        rules.append(dict(entry, sample=status, sha256=sha256_bytes((out / entry["rule_file"]).read_bytes())))
    correlations = [dict(entry, sha256=sha256_bytes((out / entry["rule_file"]).read_bytes()))
                    for entry in generated["correlations"]]
    return {
        "protocol": sample["protocol"],
        "seed": sample["seed"],
        "generated_at_commit": commit,
        "options": {"deterministic": True, "date": DRAW_DATE, "rules": "default rule per technique, product windows",
                    "correlations": "default correlation rules, every step product windows"},
        "attack": sample["attack"],
        "counts": {
            "rules": {tier: sum(1 for r in rules if r["tier"] == tier) for tier in sample["quota"]},
            "correlations": {kind: sum(1 for c in correlations if c["type"] == kind) for kind in EXPECTED_CORRELATIONS},
        },
        "rules": rules,
        "correlations": correlations,
    }


def freeze(directory: Path = POPULATION_DIR, sample_path: Path = SAMPLE_PATH) -> dict[str, Any]:
    if directory.exists():
        raise PopulationError(f"{directory} already exists; the population is frozen once. Compare with: "
                              "python -m tools.population check")
    sample = load_sample(sample_path)
    with tempfile.TemporaryDirectory(prefix="population-") as scratch:
        out = Path(scratch)
        generated = generate_at(sample["seed"], out)
        problems = verify_generated(generated, out, sample)
        if problems:
            raise PopulationError("the generated population does not match the protocol and the draw:\n" + "\n".join(problems))
        manifest = manifest_for(generated, out, sample, sample["seed"])
        directory.mkdir(parents=True)
        for sub in ("rules", "correlations"):
            shutil.copytree(out / sub, directory / sub)
        write_text(directory / MANIFEST_NAME, json.dumps(manifest, indent=1, ensure_ascii=False) + "\n")
    return manifest


def check_frozen(directory: Path = POPULATION_DIR, validation_dir: Path = VALIDATION_DIR) -> list[str]:
    """Offline: every frozen file has the hash its manifest records, and the sampled rules are the draw's files."""
    population = load_population(directory)
    sample_files = {r["technique_id"]: r["rule_file"] for rules in load_sample(validation_dir / "sample.json")["strata"].values()
                    for r in rules if r.get("selected")}
    problems = []
    listed = {entry["rule_file"] for entry in population["rules"] + population["correlations"]}
    on_disk = {p.relative_to(directory).as_posix() for p in directory.glob("*/*.yml")}
    for extra in sorted(on_disk - listed):
        problems.append(f"{extra}: not in {MANIFEST_NAME}")
    for entry in population["rules"] + population["correlations"]:
        path = directory / entry["rule_file"]
        if not path.is_file():
            problems.append(f"{entry['rule_file']}: missing")
        elif sha256_bytes(path.read_bytes()) != entry["sha256"]:
            problems.append(f"{entry['rule_file']}: sha256 differs from {MANIFEST_NAME}")
    for entry in population["rules"]:
        if entry["technique_id"] in sample_files:
            drawn = (validation_dir / sample_files[entry["technique_id"]]).read_bytes()
            if (directory / entry["rule_file"]).read_bytes() != drawn:
                problems.append(f"{entry['rule_file']}: differs from the drawn {sample_files[entry['technique_id']]}")
    return problems


def check(directory: Path = POPULATION_DIR) -> list[str]:
    """Regenerate at the protocol commit and compare with the frozen files byte for byte."""
    problems = check_frozen(directory)
    population = load_population(directory)
    with tempfile.TemporaryDirectory(prefix="population-") as scratch:
        out = Path(scratch)
        generated = generate_at(population["generated_at_commit"], out)
        regenerated = {e["rule_file"] for e in generated["rules"] + generated["correlations"]}
        frozen = {e["rule_file"] for e in population["rules"] + population["correlations"]}
        for name in sorted(regenerated ^ frozen):
            problems.append(f"{name}: {'only regenerated' if name in regenerated else 'only frozen'}")
        for name in sorted(regenerated & frozen):
            if (out / name).read_bytes() != (directory / name).read_bytes():
                problems.append(f"{name}: regenerated file differs")
    return problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.population", description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=["freeze", "check"])
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            manifest = freeze()
            counts = manifest["counts"]
            print(f"Froze {sum(counts['rules'].values())} rules {counts['rules']} and "
                  f"{sum(counts['correlations'].values())} correlation rules {counts['correlations']} "
                  f"generated at {manifest['generated_at_commit'][:7]} into {POPULATION_DIR.relative_to(ROOT)}")
            return 0
        problems = check()
        for problem in problems:
            print(problem)
        print("Frozen population matches the protocol commit" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    except (PopulationError, corpus.CorpusError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
