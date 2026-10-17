"""False-positive scoring over benign host-days (protocol sections 6, 10 and 11).

Reads what ``tools/lab/Export-BenignDay.ps1`` writes on every benign host, one folder per host and UTC day
(``<benign>/<COMPUTERNAME>/<yyyy-MM-dd>/`` with the day's ``.evtx`` and ``host-day.json``), and the frozen
false-positive population (``docs/validation/population/``, amendment 4).

    python -m tools.benign convert --benign DIR   # convert the population; load-check every rule in Hayabusa
    python -m tools.benign run --benign DIR       # Hayabusa over each host's exported days, population loaded
    python -m tools.benign report --benign DIR --real-endpoint NAME
    python -m tools.benign all --benign DIR --real-endpoint NAME

The pinned converter and Hayabusa come from ``python -m tools.score fetch``. ``report`` writes, to
``output/benign-scores/`` by default:

* ``host-days.csv``: every exported day of every host, whether it counts, and every reason it does not;
* ``alerts.csv``: every alert before deduplication: original and converted rule ID, host label, UTC
  timestamp, channel and event ID, and never event contents;
* ``rules.csv``: per rule, alert-days and host-days on the real endpoint and on the lab VMs, with and
  without the 4-active-hour minimum (the sensitivity check of section 11);
* ``conversion-manifest.json`` and ``benign.md``.

How the protocol's text is applied where it left a choice is recorded in its amendment 4.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import population as pop  # noqa: E402
from tools import score  # noqa: E402
from tools.score import ScoreError  # noqa: E402

WORK = score.SCORE_DIR / "benign"
DEFAULT_BENIGN = ROOT / "output" / "benign"
DEFAULT_OUT = ROOT / "output" / "benign-scores"
DEFAULT_LAB_DAYS = ROOT / "output" / "round1" / "lab-record" / "lab-days.txt"

MIN_ACTIVE_HOURS = 4
#: The channels whose retention decides a host-day; classic Windows PowerShell is exported but does not.
DECIDING_CHANNELS = ("Microsoft-Windows-Sysmon/Operational", "Security", "System",
                     "Microsoft-Windows-PowerShell/Operational")

REASON_LOGS = "logs do not cover the day"
REASON_CLEAR = "log cleared"
REASON_CONFIG = "Sysmon configuration changed"
REASON_GAP = "Sysmon gap"
REASON_ACTIVE = f"fewer than {MIN_ACTIVE_HOURS} active hours"
REASON_LAB = "lab work on the real endpoint"
REASON_RECORD = "no host-day.json"

ENDPOINT, LAB = "real_endpoint", "lab_vm"
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# --------------------------------------------------------------------------- #
# Host-days
# --------------------------------------------------------------------------- #
@dataclass
class HostDay:
    computer: str
    role: str
    label: str
    day: str
    active_hours: Optional[int]
    reasons: list[str] = field(default_factory=list)

    @property
    def primary(self) -> bool:
        """Counts in every primary measure: no reason applies (protocol section 6)."""
        return not self.reasons

    @property
    def without_minimum(self) -> bool:
        """Counts in the sensitivity check: the 4-active-hour minimum is the only reason, if any (section 11)."""
        return all(reason == REASON_ACTIVE for reason in self.reasons)


def day_reasons(record: dict[str, Any], lab_day: bool) -> list[str]:
    """Every reason a day is not a benign host-day, from the evidence Export-BenignDay.ps1 recorded."""
    reasons = []
    covering = {log.get("channel"): bool(log.get("covers_day")) for log in record.get("logs") or []}
    if not all(covering.get(channel) for channel in DECIDING_CHANNELS):
        reasons.append(REASON_LOGS)
    if int(record.get("log_clears") or 0):
        reasons.append(REASON_CLEAR)
    if int(record.get("sysmon_config_changes") or 0):
        reasons.append(REASON_CONFIG)
    if int(record.get("sysmon_gaps") or 0):
        reasons.append(REASON_GAP)
    if int(record.get("active_hours") or 0) < MIN_ACTIVE_HOURS:
        reasons.append(REASON_ACTIVE)
    if lab_day:
        reasons.append(REASON_LAB)
    return reasons


def read_lab_days(path: Optional[Path]) -> set[str]:
    """UTC dates of lab work on the real endpoint: one date and the activity per line (lab-build.md)."""
    if path is None or not path.is_file():
        return set()
    days = set()
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        token = text.split()[0]
        if not _DAY.match(token):
            raise ScoreError(f"{path}:{number}: expected a UTC date (yyyy-MM-dd) first, got {token!r}")
        date.fromisoformat(token)
        days.add(token)
    return days


def host_folders(benign: Path) -> list[Path]:
    if not benign.is_dir():
        raise ScoreError(f"{benign} does not exist; pass --benign with the folder holding one folder per host")
    return sorted(p for p in benign.iterdir() if p.is_dir() and any(_DAY.match(d.name) for d in p.iterdir()))


def labels_for(hosts: Sequence[str], real_endpoint: Optional[str]) -> dict[str, tuple[str, str]]:
    """Computer name -> (role, published label). The real endpoint's name is never published."""
    if real_endpoint and not any(score.same_host(host, real_endpoint) for host in hosts):
        raise ScoreError(f"--real-endpoint {real_endpoint} has no folder among: {', '.join(hosts) or 'none'}")
    labels: dict[str, tuple[str, str]] = {}
    number = 0
    for host in sorted(hosts, key=str.upper):
        if real_endpoint and score.same_host(host, real_endpoint):
            labels[host] = (ENDPOINT, "real-endpoint")
        else:
            number += 1
            labels[host] = (LAB, f"lab-vm-{number}")
    return labels


def load_host_days(benign: Path, real_endpoint: Optional[str], lab_days: set[str]) -> list[HostDay]:
    folders = host_folders(benign)
    labels = labels_for([f.name for f in folders], real_endpoint)
    days: list[HostDay] = []
    for folder in folders:
        role, label = labels[folder.name]
        for day_dir in sorted(d for d in folder.iterdir() if d.is_dir() and _DAY.match(d.name)):
            path = day_dir / "host-day.json"
            if not path.is_file():
                days.append(HostDay(folder.name, role, label, day_dir.name, None, [REASON_RECORD]))
                continue
            record = json.loads(path.read_text(encoding="utf-8-sig"))
            if str(record.get("day_utc")) != day_dir.name:
                raise ScoreError(f"{path}: day_utc {record.get('day_utc')!r} does not match its folder")
            reasons = day_reasons(record, role == ENDPOINT and day_dir.name in lab_days)
            # The exporter's own verdict covers every condition but lab work; a disagreement means the
            # evidence and the verdict were not written together.
            if bool(record.get("complete")) != (not [r for r in reasons if r != REASON_LAB]):
                raise ScoreError(f"{path}: 'complete' is {record.get('complete')} but the evidence says {reasons}")
            days.append(HostDay(folder.name, role, label, day_dir.name, int(record.get("active_hours") or 0), reasons))
    return days


# --------------------------------------------------------------------------- #
# Conversion and load check
# --------------------------------------------------------------------------- #
def population_files(population: dict[str, Any], directory: Path = pop.POPULATION_DIR) -> list[Path]:
    return [directory / entry["rule_file"] for entry in population["rules"] + population["correlations"]]


def smallest_evtx(benign: Path) -> Path:
    files = sorted(benign.rglob("*.evtx"), key=lambda p: (p.stat().st_size, str(p)))
    if not files:
        raise ScoreError(f"no .evtx under {benign}; pass --load-check-evtx with any event log file")
    return files[0]


def hayabusa(exe: Path, logs: Path, rules: Path, output: Path) -> dict[str, Any]:
    command = [str(exe), *score.HAYABUSA_ARGS, "-d", str(logs.resolve()), "-r", str(rules.resolve()),
               "-o", str(output.resolve())]
    done = subprocess.run(command, cwd=str(exe.parent), capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    run: dict[str, Any] = dict(score.parse_hayabusa_summary(done.stdout + done.stderr))
    run["exit_code"] = done.returncode
    run["command"] = ["hayabusa", *command[1:]]
    return run


def convert(population: dict[str, Any], evtx: Path, platform: str) -> dict[str, Any]:
    """Convert the whole population in one converter run, then load each rule's converted files on their own
    in Hayabusa (over one small event log, which only has to exist) to find conversion failures (section 7,
    amendment 3). The converted files of every rule that loads cleanly go to ``loaded/`` for ``run``."""
    exe = score.hayabusa_exe(platform)
    if not exe.is_file():
        raise ScoreError("Hayabusa is not fetched. Run: python -m tools.score fetch")
    rules = score.run_converter(population_files(population), WORK)
    converted, loaded, check = WORK / "converted", WORK / "loaded", WORK / "load-check"
    for folder in (loaded, check):
        shutil.rmtree(folder, ignore_errors=True)
    (check / "logs").mkdir(parents=True)
    shutil.copy2(evtx, check / "logs" / "check.evtx")
    for rule_id, entry in rules.items():
        if not entry["converted"]:
            entry["conversion"] = "the converter produced no rule"
            continue
        one = check / "rules" / rule_id
        for item in entry["converted"]:
            (one / item["file"]).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(converted / item["file"], one / item["file"])
        run = hayabusa(exe, check / "logs", one, check / "alerts.jsonl")
        entry["load_check"] = {key: run.get(key) for key in ("rule_parsing_errors", "total_detection_rules")}
        reason = score.refused(run, len(entry["converted"]))
        entry["conversion"] = f"failed: {reason}" if reason else "ok"
        if not reason:
            for item in entry["converted"]:
                (loaded / item["file"]).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(converted / item["file"], loaded / item["file"])
    manifest = {"converter": {"commit": score.CONVERTER_COMMIT, "files": score.CONVERTER_FILES,
                              "requirements": score.CONVERTER_REQUIREMENTS},
                "hayabusa": {"version": score.HAYABUSA_VERSION, "tag_commit": score.HAYABUSA_TAG_COMMIT},
                "load_check_evtx": evtx.name,
                "loaded_rules": sum(len(e["converted"]) for e in rules.values() if e["conversion"] == "ok"),
                "rules": rules}
    (WORK / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    failed = sum(1 for e in rules.values() if e["conversion"] != "ok")
    print(f"Converted and load-checked {len(rules)} rules: {len(rules) - failed} load, {failed} conversion failure(s)")
    return manifest


def load_manifest() -> dict[str, Any]:
    path = WORK / "manifest.json"
    if not path.is_file():
        raise ScoreError("no benign conversion manifest. Run: python -m tools.benign convert")
    return json.loads(path.read_text(encoding="utf-8"))


def run(benign: Path, platform: str) -> None:
    """One Hayabusa run per host over every day it exported, with every cleanly loading rule (section 10)."""
    exe = score.hayabusa_exe(platform)
    manifest = load_manifest()
    for folder in host_folders(benign):
        out = WORK / "runs" / folder.name
        out.mkdir(parents=True, exist_ok=True)
        result = hayabusa(exe, folder, WORK / "loaded", out / "alerts.jsonl")
        result["expected_rules"] = manifest["loaded_rules"]
        (out / "hayabusa.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
        reason = score.refused(result, manifest["loaded_rules"])
        if reason:
            raise ScoreError(f"{folder.name}: {reason}, although each rule loaded on its own; see {out}")
        print(f"{folder.name}: Hayabusa ran with {manifest['loaded_rules']} converted rule(s)")


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
@dataclass
class RuleNoise:
    rule_id: str
    kind: str                 # rule | correlation
    technique_id: str
    tier: str
    type: str                 # the correlation type, empty for a rule
    conversion: str
    alert_days: dict[tuple[str, str], int] = field(default_factory=dict)   # (role, day set) -> alert-days
    host_days: dict[tuple[str, str], int] = field(default_factory=dict)

    def rate(self, role: str, days: str) -> Optional[float]:
        if self.conversion != "ok" or not self.host_days.get((role, days)):
            return None
        return self.alert_days.get((role, days), 0) / self.host_days[(role, days)]


DAY_SETS = ("primary", "without_minimum")
RULE_COLUMNS = ["rule_id", "kind", "technique_id", "tier", "type", "conversion",
                *[f"{role}_{days}_{measure}" for role in (ENDPOINT, LAB) for days in DAY_SETS
                  for measure in ("alert_days", "host_days", "rate")]]
DAY_COLUMNS = ["host", "role", "day", "active_hours", "primary", "without_minimum", "reasons"]
ALERT_COLUMNS = ["rule_id", "kind", "technique_id", "converted_rule_id", "host", "timestamp", "channel",
                 "event_id", "day", "counted_primary", "counted_without_minimum"]


def report(benign: Path, out: Path, real_endpoint: Optional[str], lab_days_path: Optional[Path],
           population: Optional[dict[str, Any]] = None, manifest: Optional[dict[str, Any]] = None,
           runs: Optional[Path] = None) -> list[RuleNoise]:
    population = population if population is not None else pop.load_population()
    rules = (manifest if manifest is not None else load_manifest())["rules"]
    runs = runs if runs is not None else WORK / "runs"
    days = load_host_days(benign, real_endpoint, read_lab_days(lab_days_path))

    noise: dict[str, RuleNoise] = {}
    for kind, entries in (("rule", population["rules"]), ("correlation", population["correlations"])):
        for entry in entries:
            converted = rules.get(entry["rule_id"])
            conversion = "the rule is missing from the conversion manifest" if converted is None \
                else converted.get("conversion", "not load-checked")
            noise[entry["rule_id"]] = RuleNoise(entry["rule_id"], kind, entry["technique_id"], entry["tier"],
                                                entry.get("type", ""), conversion)
    original_of = {item["id"]: rule_id for rule_id, entry in rules.items() for item in entry.get("converted", [])}

    by_host_day = {(d.computer, d.day): d for d in days}
    for role in (ENDPOINT, LAB):
        for day_set in DAY_SETS:
            count = sum(1 for d in days if d.role == role and getattr(d, day_set))
            for item in noise.values():
                item.host_days[(role, day_set)] = count

    alert_rows: list[dict[str, Any]] = []
    seen: dict[str, set[tuple[str, str, str]]] = {day_set: set() for day_set in DAY_SETS}
    computers = sorted({d.computer for d in days})
    labels = {d.computer: (d.role, d.label) for d in days}
    for computer in computers:
        run_info = runs / computer / "hayabusa.json"
        if not run_info.is_file():
            raise ScoreError(f"no Hayabusa run for {computer}. Run: python -m tools.benign run")
        role, label = labels[computer]
        for alert in score.read_alerts(runs / computer / "alerts.jsonl"):
            converted_id = str(alert.get("RuleID", ""))
            original = original_of.get(converted_id)
            if original is None or original not in noise:
                raise ScoreError(f"{computer}: alert from rule {converted_id}, which no frozen rule was converted into")
            item = noise[original]
            if item.conversion != "ok":
                continue            # a conversion failure is left out of every noise measure (section 7)
            if not score.same_host(str(alert.get("Computer", "")), computer):
                raise ScoreError(f"{computer}: alert for computer {alert.get('Computer')!r} in this host's logs")
            when = score.parse_time(str(alert["Timestamp"]))
            day = when.date().isoformat()
            host_day = by_host_day.get((computer, day))
            row = {"rule_id": original, "kind": item.kind, "technique_id": item.technique_id,
                   "converted_rule_id": converted_id, "host": label, "timestamp": when.isoformat(timespec="milliseconds"),
                   "channel": alert.get("Channel", ""), "event_id": alert.get("EventID", ""), "day": day}
            for day_set in DAY_SETS:
                counted = bool(host_day and getattr(host_day, day_set))
                row[f"counted_{day_set}"] = "yes" if counted else "no"
                if counted:
                    seen[day_set].add((original, computer, day))
            alert_rows.append(row)
    for day_set in DAY_SETS:
        for original, computer, _ in seen[day_set]:
            key = (labels[computer][0], day_set)
            noise[original].alert_days[key] = noise[original].alert_days.get(key, 0) + 1

    out.mkdir(parents=True, exist_ok=True)
    score._write_csv(out / "host-days.csv", DAY_COLUMNS, [
        {"host": d.label, "role": d.role, "day": d.day, "active_hours": "" if d.active_hours is None else d.active_hours,
         "primary": "yes" if d.primary else "no", "without_minimum": "yes" if d.without_minimum else "no",
         "reasons": "; ".join(d.reasons)} for d in days])
    score._write_csv(out / "alerts.csv", ALERT_COLUMNS,
                     sorted(alert_rows, key=lambda r: (r["host"], r["timestamp"], r["rule_id"])))
    score._write_csv(out / "rules.csv", RULE_COLUMNS, [_noise_dict(item) for item in noise.values()])
    (out / "conversion-manifest.json").write_text(json.dumps(rules, indent=1) + "\n", encoding="utf-8")
    (out / "benign.md").write_text(render_markdown(days, list(noise.values())), encoding="utf-8")
    return list(noise.values())


def _noise_dict(item: RuleNoise) -> dict[str, Any]:
    row: dict[str, Any] = {"rule_id": item.rule_id, "kind": item.kind, "technique_id": item.technique_id,
                           "tier": item.tier, "type": item.type, "conversion": item.conversion}
    for role in (ENDPOINT, LAB):
        for day_set in DAY_SETS:
            rate = item.rate(role, day_set)
            ok = item.conversion == "ok"
            row[f"{role}_{day_set}_alert_days"] = item.alert_days.get((role, day_set), 0) if ok else ""
            row[f"{role}_{day_set}_host_days"] = item.host_days.get((role, day_set), 0)
            row[f"{role}_{day_set}_rate"] = "" if rate is None else f"{rate:.4f}"
    return row


def render_markdown(days: Sequence[HostDay], noise: Sequence[RuleNoise]) -> str:
    lines = ["| Host | Role | Days exported | Host-days | Host-days without the 4-hour minimum | Excluded |",
             "|---|---|---|---|---|---|"]
    for label in sorted({d.label for d in days}):
        own = [d for d in days if d.label == label]
        lines.append(f"| {label} | {own[0].role} | {len(own)} | {sum(d.primary for d in own)} "
                     f"| {sum(d.without_minimum for d in own)} | {sum(not d.primary for d in own)} |")
    excluded = [d for d in days if not d.primary]
    lines += ["", "Excluded days (protocol section 10):", ""]
    if excluded:
        lines += ["| Host | Day | Reasons |", "|---|---|---|"]
        lines += [f"| {d.label} | {d.day} | {'; '.join(d.reasons)} |" for d in excluded]
    else:
        lines.append("None.")
    failures = [n for n in noise if n.conversion != "ok"]
    lines += ["", f"Conversion failures, left out of every noise measure: {len(failures)} of {len(noise)} "
                  f"({sum(n.kind == 'rule' for n in failures)} rules, "
                  f"{sum(n.kind == 'correlation' for n in failures)} correlation rules)."]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #
def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.benign", description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=["convert", "run", "report", "all"])
    parser.add_argument("--benign", type=Path, default=DEFAULT_BENIGN,
                        help="folder with one folder per host, as Export-BenignDay.ps1 writes (default: output/benign)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="where report writes (default: output/benign-scores)")
    parser.add_argument("--real-endpoint", help="COMPUTERNAME of the real endpoint; every other host is a lab VM")
    parser.add_argument("--lab-days", type=Path, default=DEFAULT_LAB_DAYS,
                        help="UTC dates of lab work on the real endpoint (default: output/round1/lab-record/lab-days.txt)")
    parser.add_argument("--load-check-evtx", type=Path,
                        help="the event log the load check runs over (default: the smallest .evtx under --benign)")
    args = parser.parse_args(argv)
    try:
        platform = score.platform_key() if args.command in ("convert", "run", "all") else ""
        if args.command in ("convert", "all"):
            convert(pop.load_population(), args.load_check_evtx or smallest_evtx(args.benign), platform)
        if args.command in ("run", "all"):
            run(args.benign, platform)
        if args.command in ("report", "all"):
            noise = report(args.benign, args.out, args.real_endpoint, args.lab_days)
            print((args.out / "benign.md").read_text(encoding="utf-8"), end="")
            print(f"Wrote host-days.csv, alerts.csv, rules.csv, benign.md and conversion-manifest.json "
                  f"for {len(noise)} rules to {args.out}")
        return 0
    except (ScoreError, pop.PopulationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
