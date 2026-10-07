"""Validation scoring: Sigma to Hayabusa conversion, Hayabusa runs, and the protocol's "detected" test.

Implements docs/validation-protocol.md, sections 7 and 8, over the records the lab runner writes
(tools/lab/Invoke-Round1.ps1): one folder per ART test holding ``result.json`` and the test's ``.evtx``.

    python -m tools.score fetch     # the pinned Hayabusa release and converter, a venv for the converter
    python -m tools.score convert   # convert every rule under test; write the conversion manifest
    python -m tools.score run       # Hayabusa over each executed test's logs, with only that rule loaded
    python -m tools.score report    # per-test, per-rule and raw alert tables
    python -m tools.score all       # the four in order (`make score`)

``fetch``, ``convert`` and ``run`` need the network once and the test logs; ``report`` only reads
files, so it can be re-run anywhere the results were copied to. Nothing here edits the protocol,
the sample or the rules under test.

A test is **detected** when Hayabusa emits at least one alert that meets all three of:

1. its ``RuleID`` was derived by the converter from the rule under test (the conversion manifest);
2. its ``Computer`` is the attack host;
3. its ``Timestamp`` falls inside the execution window ``[t0 - 5 s, t1 + 60 s]``, on the VM's own clock.

It is **confounded** instead when an alert meeting 1 and 2 also falls inside the null window, the
idle period of the same length just before the execution window. Interpretations of cases the
protocol leaves open are recorded in its amendment 3.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

SAMPLE_PATH = ROOT / "docs" / "validation" / "sample.json"
VALIDATION_DIR = ROOT / "docs" / "validation"
SCORE_DIR = ROOT / "data" / "score"
DEFAULT_RESULTS = ROOT / "output" / "round1"
DEFAULT_OUT = ROOT / "output" / "round1-scores"

#: Hayabusa, pinned in the protocol at v4.1.0. Release assets: (archive, sha256, executable) per platform.
HAYABUSA_VERSION = "4.1.0"
HAYABUSA_TAG_COMMIT = "11a7f64accf9fa815a92aea1b36e174975f1df9a"
HAYABUSA_ASSETS: dict[str, tuple[str, str, str]] = {
    "win-x64": ("hayabusa-4.1.0-win-x64.zip",
                "4d304cc5baaa750ed08cc24b7b89c58ea058740c7e344502d7b82554637543a8",
                "hayabusa-4.1.0-win-x64.exe"),
    "lin-x64-gnu": ("hayabusa-4.1.0-lin-x64-gnu.zip",
                    "ed2c4595f95b8e765d37f392212587304ce89ed7cfb6682b425a96d126ed67eb",
                    "hayabusa-4.1.0-lin-x64-gnu"),
}
HAYABUSA_URL = "https://github.com/Yamato-Security/hayabusa/releases/download/v{version}/{asset}"

#: sigma-to-hayabusa-converter, pinned in the protocol at this commit; each file it needs, by sha256.
CONVERTER_COMMIT = "3786d70d362455cbd89110d36b678307c8f9c889"
CONVERTER_FILES: dict[str, str] = {
    "sigma-to-hayabusa-converter.py": "984e72f719b615096c1bd101d5ff9d444fefb00bc42b4450361bcec492f2409a",
    "sysmon-category-mapping.yaml": "ae491edc67d783eb37d0b3a0c394bba12120dda1a79d19a5f8724b059d90ccfc",
    "builtin-category-mapping.yaml": "e9ac63fbe1335f9ca41053cf8fce7acb3a8182372f2ebe8d3a09036ffd63f643",
    "services-mapping.yaml": "e9b4f2c22fa060c501eeaeedca47966c25e1569a845591e62ed53d9df150f50a",
    "ignore-uuid-list.txt": "c0a966a14eeecbd2e96a42054f8bd6695b5629a645825b53f6395b92dd4bc848",
}
#: From the converter's own poetry.lock. The converter itself needs Python 3.10 or newer.
CONVERTER_REQUIREMENTS = ["ruamel.yaml==0.18.5"]
CONVERTER_URL = "https://raw.githubusercontent.com/Yamato-Security/sigma-to-hayabusa-converter/{commit}/{name}"

#: The protocol's command (section 8), plus -q, -K and -C (amendment 3): no banner, no colour codes in the
#: summary this tool parses, and overwrite a previous run's output.
HAYABUSA_ARGS = ["dfir-timeline", "-c", "rules/config", "-w", "-m", "informational", "-n", "-D", "-u", "-U",
                 "-p", "all-field-info", "-t", "jsonl", "-q", "-K", "-C"]

PRE_WINDOW = timedelta(seconds=5)
POST_WINDOW = timedelta(seconds=60)
EXECUTED = ("executed", "execution_failed")


class ScoreError(Exception):
    """A pin, an input file or an external tool is not what the protocol expects."""


# --------------------------------------------------------------------------- #
# Time and windows
# --------------------------------------------------------------------------- #
_TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})$"
)


def parse_time(text: str) -> datetime:
    """A timezone-aware UTC datetime from the runner's ``o`` format (``2026-10-07T05:20:16.1234567Z``)
    or Hayabusa's ``-U`` format (``2026-10-07 05:20:16.123 +00:00``). A time without a zone is refused
    rather than guessed."""
    match = _TIME_RE.match(str(text).strip())
    if not match:
        raise ScoreError(f"unrecognised or zone-less timestamp: {text!r}")
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    micro = int((fraction or "0")[:6].ljust(6, "0"))
    value = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), micro, timezone.utc)
    if zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        value -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return value


@dataclass(frozen=True)
class Windows:
    execution_start: datetime
    execution_end: datetime          # inclusive
    null_start: datetime
    null_end: datetime               # exclusive; equals execution_start
    null_truncated: bool             # the execution window outlasted the quiet period

    def in_execution(self, when: datetime) -> bool:
        return self.execution_start <= when <= self.execution_end

    def in_null(self, when: datetime) -> bool:
        return self.null_start <= when < self.null_end


def windows_for(record: dict[str, Any]) -> Windows:
    """Protocol section 8, steps 5 and 7, from the runner's guest-clock timestamps."""
    t0, t1 = parse_time(record["t0_utc"]), parse_time(record["t1_utc"])
    start, end = t0 - PRE_WINDOW, t1 + POST_WINDOW
    null_start = start - (end - start)
    quiet = parse_time(record["quiet_start_utc"]) if record.get("quiet_start_utc") else None
    truncated = quiet is not None and quiet > null_start
    if truncated and quiet is not None:
        null_start = quiet
    return Windows(start, end, null_start, start, truncated)


def same_host(computer: str, attack_host: str) -> bool:
    """Hayabusa's ``Computer`` may be a bare name or a DNS name; compare the first label, ignoring case."""
    def label(name: str) -> str:
        return name.strip().split(".")[0].upper()
    return bool(computer) and label(computer) == label(attack_host)


# --------------------------------------------------------------------------- #
# Conversion manifest
# --------------------------------------------------------------------------- #
def build_manifest(staged_rules: Path, converted: Path) -> dict[str, dict[str, Any]]:
    """Original rule ID -> its file and the rules the converter derived from it.

    Converted files are traced back by their ``related: {type: derived}`` entry, never by name."""
    rules: dict[str, dict[str, Any]] = {}
    for path in sorted(staged_rules.glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules[str(document["id"])] = {"rule_file": path.name, "converted": []}
    for path in sorted(converted.rglob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for related in document.get("related") or []:
            original = str(related.get("id"))
            if related.get("type") == "derived" and original in rules:
                rules[original]["converted"].append({
                    "file": path.relative_to(converted).as_posix(),
                    "id": str(document["id"]),
                    "logsource": document.get("logsource") or {},
                })
    return rules


_SUMMARY = {
    "rule_parsing_errors": re.compile(r"Rule parsing errors:\s*(\d+)"),
    "total_detection_rules": re.compile(r"Total detection rules:\s*(\d+)"),
}
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def parse_hayabusa_summary(output: str) -> dict[str, Optional[int]]:
    text = _ANSI.sub("", output)
    found: dict[str, Optional[int]] = {}
    for key, pattern in _SUMMARY.items():
        match = pattern.search(text)
        found[key] = int(match.group(1)) if match else None
    if "No rules were loaded" in text:
        found["total_detection_rules"] = 0
    return found


def refused(run: dict[str, Any], expected_rules: int) -> Optional[str]:
    """Why Hayabusa refused the rule's converted files, or None if it loaded all of them."""
    errors = run.get("rule_parsing_errors")
    loaded = run.get("total_detection_rules")
    if errors:
        return f"Hayabusa reported {errors} rule parsing error(s)"
    if loaded is not None and loaded < expected_rules:
        return f"Hayabusa loaded {loaded} of {expected_rules} converted rule(s)"
    return None


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
@dataclass
class ArtTestScore:
    technique_id: str
    rule_id: str
    test_guid: str
    test_name: str
    outcome: str                     # detected | confounded | missed | conversion_failure | prerequisites_failed
    execution_status: str = ""
    alerts_for_rule: int = 0         # alerts whose RuleID derives from the rule, any host, any time
    in_execution_window: int = 0     # ...on the attack host, inside the execution window
    in_null_window: int = 0          # ...on the attack host, inside the null window
    other_host: int = 0
    null_truncated: bool = False
    note: str = ""


def score_test(record: dict[str, Any], alerts: Iterable[dict[str, Any]], derived_ids: set[str],
               conversion_failure: Optional[str], attack_host: str) -> ArtTestScore:
    score = ArtTestScore(
        technique_id=str(record.get("technique_id", "")), rule_id=str(record.get("rule_id", "")),
        test_guid=str(record.get("test_guid", "")), test_name=str(record.get("test_name", "")),
        outcome="missed", execution_status=str(record.get("execution_status", "")),
    )
    if record.get("prereq_status") != "met":
        score.outcome = "prerequisites_failed"
        return score
    if score.execution_status not in EXECUTED:
        raise ScoreError(f"{score.test_guid}: unknown execution status {score.execution_status!r}")
    if conversion_failure:
        score.outcome, score.note = "conversion_failure", conversion_failure
        return score

    windows = windows_for(record)
    score.null_truncated = windows.null_truncated
    for alert in alerts:
        if str(alert.get("RuleID", "")) not in derived_ids:
            continue
        score.alerts_for_rule += 1
        if not same_host(str(alert.get("Computer", "")), attack_host):
            score.other_host += 1
            continue
        when = parse_time(str(alert["Timestamp"]))
        if windows.in_execution(when):
            score.in_execution_window += 1
        elif windows.in_null(when):
            score.in_null_window += 1
    if score.in_execution_window:
        score.outcome = "confounded" if score.in_null_window else "detected"
    return score


@dataclass
class RuleScore:
    tier: str
    rank: int
    technique_id: str
    rule_id: str
    art_tests: int
    conversion: str = "ok"
    recorded: int = 0
    prerequisites_failed: int = 0
    executed: int = 0
    execution_failed: int = 0
    detected: int = 0
    confounded: int = 0
    missed: int = 0
    null_truncated: int = 0
    harness_errors: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def detection_rate(self) -> Optional[float]:
        """Detected tests over executed tests (protocol section 11); 0 for a conversion failure."""
        return self.detected / self.executed if self.executed else None


def score_rules(sample: dict[str, Any], tests: Sequence[ArtTestScore], conversion: dict[str, Optional[str]],
                harness_errors: dict[str, int]) -> list[RuleScore]:
    """One row per rule that has any record, in tier and draw order."""
    by_rule: dict[str, list[ArtTestScore]] = {}
    for test in tests:
        by_rule.setdefault(test.rule_id, []).append(test)
    rows: list[RuleScore] = []
    for tier in ("strong", "moderate", "weak"):
        for rule in sample["strata"][tier]:
            rule_id = rule.get("rule_id")
            if not rule_id or (rule_id not in by_rule and not harness_errors.get(rule_id)):
                continue
            row = RuleScore(tier, int(rule["rank"]), rule["technique_id"], rule_id, len(rule["art_tests"]))
            if conversion.get(rule_id):
                row.conversion = f"failed: {conversion[rule_id]}"
            row.harness_errors = harness_errors.get(rule_id, 0)
            for test in by_rule.get(rule_id, []):
                row.recorded += 1
                if test.outcome == "prerequisites_failed":
                    row.prerequisites_failed += 1
                    continue
                row.executed += 1
                row.execution_failed += test.execution_status == "execution_failed"
                row.null_truncated += test.null_truncated
                if test.outcome == "detected":
                    row.detected += 1
                elif test.outcome == "confounded":
                    row.confounded += 1
                else:
                    row.missed += 1
            if row.recorded and not row.executed:
                row.notes.append("every recorded test failed prerequisites: substitute per protocol section 4")
            if row.recorded + row.harness_errors < row.art_tests:
                row.notes.append(f"{row.art_tests - row.recorded - row.harness_errors} mapped test(s) not run yet")
            rows.append(row)
    return rows


# --------------------------------------------------------------------------- #
# Reading the runner's records
# --------------------------------------------------------------------------- #
def load_records(results: Path) -> tuple[list[tuple[Path, dict[str, Any]]], dict[str, int]]:
    """``(test folder, result.json)`` for every recorded ART test, and harness errors per rule ID."""
    records: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(results.glob("*/*/result.json")):
        record = json.loads(path.read_text(encoding="utf-8-sig"))
        if not record.get("smoke_test"):
            records.append((path.parent, record))
    errors: dict[str, int] = {}
    for path in sorted(results.glob("*/*/harness-error.json")):
        record = json.loads(path.read_text(encoding="utf-8-sig"))
        if not record.get("smoke_test"):
            errors[str(record.get("rule_id", ""))] = errors.get(str(record.get("rule_id", "")), 0) + 1
    return records, errors


def read_alerts(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def attack_host_of(record: dict[str, Any], override: Optional[str]) -> str:
    if override:
        return override
    host = (record.get("preflight") or {}).get("computer")
    if not host:
        raise ScoreError(f"{record.get('test_guid')}: result.json has no preflight.computer; pass --attack-host")
    return str(host)


# --------------------------------------------------------------------------- #
# External steps: fetch, convert, run
# --------------------------------------------------------------------------- #
def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _download(url: str, expected_sha256: str) -> bytes:
    import requests

    response = requests.get(url, timeout=300)
    response.raise_for_status()
    actual = _sha256(response.content)
    if actual != expected_sha256:
        raise ScoreError(f"{url} has sha256 {actual}, expected {expected_sha256}")
    return response.content


def platform_key() -> str:
    if sys.platform.startswith("win"):
        return "win-x64"
    if sys.platform.startswith("linux"):
        return "lin-x64-gnu"
    raise ScoreError(f"no pinned Hayabusa build for {sys.platform}; score on Windows or Linux")


def hayabusa_dir(platform: str) -> Path:
    return SCORE_DIR / f"hayabusa-{HAYABUSA_VERSION}-{platform}"


def hayabusa_exe(platform: str) -> Path:
    return hayabusa_dir(platform) / HAYABUSA_ASSETS[platform][2]


def converter_dir() -> Path:
    return SCORE_DIR / f"converter-{CONVERTER_COMMIT[:7]}"


def venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if sys.platform.startswith("win") else "bin/python")


def fetch(platform: str, converter_python: str) -> None:
    asset, digest, exe = HAYABUSA_ASSETS[platform]
    target = hayabusa_dir(platform)
    if not (target / exe).is_file():
        print(f"Downloading {asset}")
        data = _download(HAYABUSA_URL.format(version=HAYABUSA_VERSION, asset=asset), digest)
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            archive.extractall(target)
        (target / exe).chmod(0o755)
    print(f"Hayabusa {HAYABUSA_VERSION} at {target.relative_to(ROOT)}")

    conv = converter_dir()
    conv.mkdir(parents=True, exist_ok=True)
    for name, digest in CONVERTER_FILES.items():
        path = conv / name
        if path.is_file() and _sha256(path.read_bytes()) == digest:
            continue
        path.write_bytes(_download(CONVERTER_URL.format(commit=CONVERTER_COMMIT, name=name), digest))
    print(f"sigma-to-hayabusa-converter {CONVERTER_COMMIT[:7]} at {conv.relative_to(ROOT)}")

    version = subprocess.run([converter_python, "-c", "import sys; print(sys.version_info[:2] >= (3, 10))"],
                             capture_output=True, text=True, check=True).stdout.strip()
    if version != "True":
        raise ScoreError(f"the converter needs Python 3.10 or newer; {converter_python} is older. "
                         "Pass --converter-python with a newer interpreter.")
    venv = SCORE_DIR / "convenv"
    if not venv_python(venv).is_file():
        subprocess.run([converter_python, "-m", "venv", str(venv)], check=True)
    subprocess.run([str(venv_python(venv)), "-m", "pip", "install", "-q", *CONVERTER_REQUIREMENTS], check=True)
    print(f"Converter environment at {venv.relative_to(ROOT)}")


def convert(sample: dict[str, Any]) -> dict[str, Any]:
    """Convert every rule under test (the sampled rules' frozen files) and write manifest.json."""
    conv, venv = converter_dir(), SCORE_DIR / "convenv"
    for name, digest in CONVERTER_FILES.items():
        if not (conv / name).is_file() or _sha256((conv / name).read_bytes()) != digest:
            raise ScoreError("the pinned converter is missing or altered. Run: python -m tools.score fetch")
    # The converter only converts files under a folder whose path contains "rule".
    staged = SCORE_DIR / "stage" / "rules"
    converted = SCORE_DIR / "converted"
    for folder in (staged, converted):
        shutil.rmtree(folder, ignore_errors=True)
    staged.mkdir(parents=True)
    for tier in ("strong", "moderate", "weak"):
        for rule in sample["strata"][tier]:
            if rule.get("rule_file"):
                shutil.copy2(VALIDATION_DIR / rule["rule_file"], staged / Path(rule["rule_file"]).name)
    # The converter reads ignore-uuid-list.txt from the working directory, so it runs from its own folder.
    run = subprocess.run([str(venv_python(venv)), "sigma-to-hayabusa-converter.py", "-r", str(staged),
                          "-o", str(converted)], cwd=str(conv), capture_output=True, text=True)
    log = run.stdout + run.stderr
    (SCORE_DIR / "converter.log").write_text(log, encoding="utf-8")
    if run.returncode != 0:
        raise ScoreError(f"the converter exited with {run.returncode}; see data/score/converter.log")
    rules = build_manifest(staged, converted)
    for rule_id, entry in rules.items():
        entry["converter_messages"] = [line for line in log.splitlines() if entry["rule_file"] in line]
        per_rule = SCORE_DIR / "per-rule" / rule_id
        shutil.rmtree(per_rule, ignore_errors=True)
        per_rule.mkdir(parents=True)
        for item in entry["converted"]:
            target = per_rule / item["file"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(converted / item["file"], target)
    manifest = {"converter": {"commit": CONVERTER_COMMIT, "files": CONVERTER_FILES,
                              "requirements": CONVERTER_REQUIREMENTS},
                "hayabusa": {"version": HAYABUSA_VERSION, "tag_commit": HAYABUSA_TAG_COMMIT},
                "rules": rules}
    (SCORE_DIR / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    without = [rule["rule_file"] for rule in rules.values() if not rule["converted"]]
    print(f"Converted {len(rules) - len(without)} of {len(rules)} rules; no output for: {', '.join(without) or 'none'}")
    return manifest


def load_manifest() -> dict[str, Any]:
    path = SCORE_DIR / "manifest.json"
    if not path.is_file():
        raise ScoreError("no conversion manifest. Run: python -m tools.score convert")
    return json.loads(path.read_text(encoding="utf-8"))


def run_hayabusa(results: Path, platform: str) -> None:
    """Run Hayabusa over each executed test's logs with only its rule's converted files loaded."""
    exe = hayabusa_exe(platform)
    if not exe.is_file():
        raise ScoreError("Hayabusa is not fetched. Run: python -m tools.score fetch")
    manifest = load_manifest()["rules"]
    records, _ = load_records(results)
    for folder, record in records:
        if record.get("prereq_status") != "met":
            continue
        entry = manifest.get(str(record.get("rule_id")))
        run: dict[str, Any] = {"rule_id": record.get("rule_id"), "expected_rules": 0}
        if not entry or not entry["converted"]:
            run["skipped"] = "the converter produced no rule for the rule under test"
        else:
            run["expected_rules"] = len(entry["converted"])
            command = [str(exe), *HAYABUSA_ARGS, "-d", str(folder.resolve()),
                       "-r", str((SCORE_DIR / "per-rule" / record["rule_id"]).resolve()),
                       "-o", str((folder / "alerts.jsonl").resolve())]
            done = subprocess.run(command, cwd=str(hayabusa_dir(platform)), capture_output=True, text=True,
                                  encoding="utf-8", errors="replace")
            run.update(parse_hayabusa_summary(done.stdout + done.stderr))
            run["exit_code"] = done.returncode
            run["command"] = ["hayabusa", *command[1:]]
        (folder / "hayabusa.json").write_text(json.dumps(run, indent=1) + "\n", encoding="utf-8")
    print(f"Hayabusa ran over {sum(1 for _, r in records if r.get('prereq_status') == 'met')} executed test(s)")


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
RULE_COLUMNS = ["tier", "rank", "technique_id", "rule_id", "conversion", "art_tests", "recorded",
                "prerequisites_failed", "executed", "execution_failed", "detected", "confounded", "missed",
                "detection_rate", "null_truncated", "harness_errors", "notes"]
TEST_COLUMNS = ["technique_id", "rule_id", "test_guid", "test_name", "outcome", "execution_status",
                "alerts_for_rule", "in_execution_window", "in_null_window", "other_host", "null_truncated", "note"]
ALERT_COLUMNS = ["technique_id", "rule_id", "test_guid", "converted_rule_id", "timestamp", "computer",
                 "channel", "event_id", "placement"]


def report(results: Path, out: Path, attack_host: Optional[str] = None,
           sample: Optional[dict[str, Any]] = None, manifest: Optional[dict[str, Any]] = None) -> list[RuleScore]:
    sample = sample if sample is not None else json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    rules = (manifest if manifest is not None else load_manifest())["rules"]
    records, harness_errors = load_records(results)

    conversion: dict[str, Optional[str]] = {}
    for rule_id, entry in rules.items():
        conversion[rule_id] = None if entry["converted"] else "the converter produced no rule"
    for folder, record in records:
        run_path = folder / "hayabusa.json"
        if record.get("prereq_status") == "met" and run_path.is_file():
            run = json.loads(run_path.read_text(encoding="utf-8"))
            reason = refused(run, int(run.get("expected_rules") or 0)) if not run.get("skipped") else None
            if reason and not conversion.get(str(record["rule_id"])):
                conversion[str(record["rule_id"])] = reason

    tests: list[ArtTestScore] = []
    alert_rows: list[dict[str, Any]] = []
    for folder, record in records:
        rule_id = str(record.get("rule_id", ""))
        entry = rules.get(rule_id)
        if entry is None:
            raise ScoreError(f"{folder}: rule {rule_id} is not in the conversion manifest; only frozen rule "
                             "files under docs/validation/rules/ can be scored")
        derived = {item["id"] for item in entry["converted"]}
        failure = conversion.get(rule_id)
        executed = record.get("prereq_status") == "met"
        if executed and not failure and not (folder / "hayabusa.json").is_file():
            raise ScoreError(f"{folder}: no hayabusa.json. Run: python -m tools.score run")
        alerts = read_alerts(folder / "alerts.jsonl")
        host = attack_host_of(record, attack_host) if executed else ""
        test = score_test(record, alerts, derived, failure, host)
        tests.append(test)
        if executed and not failure:
            windows = windows_for(record)
            for alert in alerts:
                if str(alert.get("RuleID", "")) not in derived:
                    continue
                when = parse_time(str(alert["Timestamp"]))
                placement = ("other host" if not same_host(str(alert.get("Computer", "")), host)
                             else "execution window" if windows.in_execution(when)
                             else "null window" if windows.in_null(when) else "outside both windows")
                alert_rows.append({"technique_id": test.technique_id, "rule_id": rule_id, "test_guid": test.test_guid,
                                   "converted_rule_id": alert.get("RuleID"), "timestamp": alert.get("Timestamp"),
                                   "computer": alert.get("Computer"), "channel": alert.get("Channel"),
                                   "event_id": alert.get("EventID"), "placement": placement})

    rows = score_rules(sample, tests, conversion, harness_errors)
    out.mkdir(parents=True, exist_ok=True)
    _write_csv(out / "rules.csv", RULE_COLUMNS, [_rule_dict(row) for row in rows])
    _write_csv(out / "tests.csv", TEST_COLUMNS, [vars(test) for test in tests])
    _write_csv(out / "alerts.csv", ALERT_COLUMNS, alert_rows)
    (out / "conversion-manifest.json").write_text(json.dumps(rules, indent=1) + "\n", encoding="utf-8")
    (out / "rules.md").write_text(render_markdown(rows), encoding="utf-8")
    return rows


def _rule_dict(row: RuleScore) -> dict[str, Any]:
    values = {column: getattr(row, column) for column in RULE_COLUMNS if column not in ("detection_rate", "notes")}
    rate = row.detection_rate
    values["detection_rate"] = "" if rate is None else f"{rate:.3f}"
    values["notes"] = "; ".join(row.notes)
    return values


def _write_csv(path: Path, columns: Sequence[str], rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(columns), lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def render_markdown(rows: Sequence[RuleScore]) -> str:
    # The same columns as the Detection table in docs/validation/RESULTS.md.
    lines = ["| Tier | Rank | Technique | Conversion | Executed | Prerequisites failed | Execution failed "
             "| Detected | Confounded | Missed | Detection rate | Null window truncated |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for row in rows:
        rate = "—" if row.detection_rate is None else f"{row.detection_rate:.2f}"
        lines.append(f"| {row.tier} | {row.rank} | {row.technique_id} | {row.conversion} "
                     f"| {row.executed} | {row.prerequisites_failed} | {row.execution_failed} | {row.detected} "
                     f"| {row.confounded} | {row.missed} | {rate} | {row.null_truncated} |")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #
def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.score", description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=["fetch", "convert", "run", "report", "all"])
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS,
                        help="the runner's results folder (default: output/round1)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="where report writes (default: output/round1-scores)")
    parser.add_argument("--attack-host", help="override the attack host name read from each result.json")
    parser.add_argument("--converter-python", default=sys.executable,
                        help="Python 3.10+ for the converter's environment (default: this interpreter)")
    args = parser.parse_args(argv)
    try:
        platform = platform_key() if args.command in ("fetch", "run", "all") else ""
        if args.command in ("fetch", "all"):
            fetch(platform, args.converter_python)
        if args.command in ("convert", "all"):
            convert(json.loads(SAMPLE_PATH.read_text(encoding="utf-8")))
        if args.command in ("run", "all"):
            run_hayabusa(args.results, platform)
        if args.command in ("report", "all"):
            rows = report(args.results, args.out, args.attack_host)
            print(render_markdown(rows), end="")
            print(f"Wrote rules.csv, tests.csv, alerts.csv, rules.md and conversion-manifest.json to {args.out}")
        return 0
    except ScoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
