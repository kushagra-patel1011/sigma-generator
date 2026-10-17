"""False-positive scoring (tools/benign.py): host-day rules and alert-day counting, on synthetic host-day
records shaped like Export-BenignDay.ps1's and synthetic alerts shaped like Hayabusa v4.1.0's JSONL."""

from __future__ import annotations

import csv
import json

import pytest

from tools import benign
from tools.score import ScoreError

CHANNELS = ["Microsoft-Windows-Sysmon/Operational", "Security", "System", "Microsoft-Windows-PowerShell/Operational",
            "Windows PowerShell"]


def _evidence(computer, day, *, active_hours=8, clears=0, config=0, gaps=0, uncovered=(), complete=None):
    logs = [{"channel": c, "file": "x.evtx", "sha256": "0", "covers_day": c not in uncovered} for c in CHANNELS]
    record = {"computer": computer, "day_utc": day, "active_hours": active_hours, "log_clears": clears,
              "sysmon_config_changes": config, "sysmon_stops": gaps, "sysmon_gaps": gaps, "logs": logs}
    if complete is None:
        complete = not benign.day_reasons(record, lab_day=False)
    record["complete"] = complete
    return record


def _host_day(root, computer, day, **evidence):
    folder = root / computer / day
    folder.mkdir(parents=True)
    # Windows PowerShell 5.1's Set-Content -Encoding UTF8 writes a byte-order mark.
    (folder / "host-day.json").write_text(json.dumps(_evidence(computer, day, **evidence)), encoding="utf-8-sig")


# --------------------------------------------------------------------------- #
# Host-days
# --------------------------------------------------------------------------- #
def test_every_reason_a_day_is_not_a_host_day_is_listed():
    record = _evidence("PC", "2026-10-01", active_hours=2, clears=1, config=1, gaps=1, uncovered=["Security"])
    assert benign.day_reasons(record, lab_day=True) == [
        benign.REASON_LOGS, benign.REASON_CLEAR, benign.REASON_CONFIG, benign.REASON_GAP, benign.REASON_ACTIVE,
        benign.REASON_LAB]
    # Classic Windows PowerShell is exported but does not decide the day.
    assert benign.day_reasons(_evidence("PC", "2026-10-01", uncovered=["Windows PowerShell"]), lab_day=False) == []


def test_the_sensitivity_check_only_relaxes_the_active_hour_minimum():
    quiet = benign.HostDay("PC", benign.ENDPOINT, "real-endpoint", "d", 2, [benign.REASON_ACTIVE])
    cleared = benign.HostDay("PC", benign.ENDPOINT, "real-endpoint", "d", 2, [benign.REASON_ACTIVE, benign.REASON_CLEAR])
    assert (quiet.primary, quiet.without_minimum) == (False, True)
    assert (cleared.primary, cleared.without_minimum) == (False, False)


def test_lab_days_exclude_only_the_real_endpoint(tmp_path):
    _host_day(tmp_path, "ENDPOINT1", "2026-10-01")
    _host_day(tmp_path, "LABVM", "2026-10-01")
    days = benign.load_host_days(tmp_path, "endpoint1.example.lan", {"2026-10-01"})
    assert {(d.label, tuple(d.reasons)) for d in days} == {("real-endpoint", (benign.REASON_LAB,)), ("lab-vm-1", ())}


def test_an_exporter_verdict_that_contradicts_its_evidence_is_refused(tmp_path):
    _host_day(tmp_path, "PC", "2026-10-01", clears=1, complete=True)
    with pytest.raises(ScoreError, match="'complete'"):
        benign.load_host_days(tmp_path, None, set())


def test_lab_days_file_takes_a_date_first_on_each_line(tmp_path):
    path = tmp_path / "lab-days.txt"
    path.write_text("# lab work\n2026-10-01 installed VirtualBox\n\n2026-10-04 runner phase 1\n", encoding="utf-8")
    assert benign.read_lab_days(path) == {"2026-10-01", "2026-10-04"}
    path.write_text("October 1st: installed VirtualBox\n", encoding="utf-8")
    with pytest.raises(ScoreError):
        benign.read_lab_days(path)
    assert benign.read_lab_days(tmp_path / "missing.txt") == set()


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def _alert(timestamp, rule_id, computer):
    return {"Timestamp": timestamp, "Computer": computer, "Channel": "Sysmon", "EventID": 1, "RuleID": rule_id,
            "Details": {"CommandLine": "personal"}}


def _scenario(tmp_path):
    data, runs = tmp_path / "benign", tmp_path / "runs"
    _host_day(data, "ENDPOINT1", "2026-10-01")
    _host_day(data, "ENDPOINT1", "2026-10-02", active_hours=2)       # counts only without the minimum
    _host_day(data, "ENDPOINT1", "2026-10-03", clears=1)             # never counts
    _host_day(data, "LABVM", "2026-10-01")
    alerts = {
        "ENDPOINT1": [_alert("2026-10-01 09:00:00.000 +00:00", "c-strong", "ENDPOINT1"),
                      _alert("2026-10-01 10:00:00.000 +00:00", "c-strong", "endpoint1.example.lan"),
                      _alert("2026-10-01 23:59:59.999 +00:00", "c-strong", "ENDPOINT1"),
                      _alert("2026-10-02 08:00:00.000 +00:00", "c-strong", "ENDPOINT1"),
                      _alert("2026-10-03 08:00:00.000 +00:00", "c-weak", "ENDPOINT1")],
        "LABVM": [_alert("2026-10-01 12:00:00.000 +00:00", "c-strong", "LABVM")],
    }
    for computer, rows in alerts.items():
        (runs / computer).mkdir(parents=True)
        (runs / computer / "hayabusa.json").write_text("{}", encoding="utf-8")
        (runs / computer / "alerts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    population = {"rules": [{"technique_id": "T1", "tier": "strong", "rule_id": "strong"},
                            {"technique_id": "T2", "tier": "weak", "rule_id": "weak"}],
                  "correlations": [{"technique_id": "T3", "tier": "strong", "type": "temporal", "rule_id": "chain"}]}
    manifest = {"rules": {"strong": {"conversion": "ok", "converted": [{"id": "c-strong"}]},
                          "weak": {"conversion": "ok", "converted": [{"id": "c-weak"}]},
                          "chain": {"conversion": "failed: Hayabusa reported 2 rule parsing error(s)",
                                    "converted": [{"id": "c-chain"}]}}}
    return data, runs, population, manifest


def test_alerts_become_alert_days_per_role_and_day_set(tmp_path):
    data, runs, population, manifest = _scenario(tmp_path)
    noise = {item.rule_id: item for item in benign.report(
        data, tmp_path / "out", "ENDPOINT1", None, population=population, manifest=manifest, runs=runs)}

    strong, weak, chain = noise["strong"], noise["weak"], noise["chain"]
    assert strong.rate(benign.ENDPOINT, "primary") == 1.0                 # three alerts on one day: one alert-day
    assert (strong.alert_days[(benign.ENDPOINT, "without_minimum")],
            strong.host_days[(benign.ENDPOINT, "without_minimum")]) == (2, 2)
    assert strong.rate(benign.LAB, "primary") == 1.0
    assert weak.rate(benign.ENDPOINT, "primary") == 0.0                   # its only alert is on an excluded day
    assert chain.rate(benign.ENDPOINT, "primary") is None                 # a conversion failure is left out

    with open(tmp_path / "out" / "alerts.csv", encoding="utf-8") as handle:
        alerts = list(csv.DictReader(handle))
    assert len(alerts) == 6 and {a["host"] for a in alerts} == {"real-endpoint", "lab-vm-1"}
    published = "".join(path.read_text(encoding="utf-8") for path in (tmp_path / "out").iterdir())
    assert "ENDPOINT1" not in published and "personal" not in published
    with open(tmp_path / "out" / "host-days.csv", encoding="utf-8") as handle:
        days = {(d["host"], d["day"]): d for d in csv.DictReader(handle)}
    assert days[("real-endpoint", "2026-10-03")]["reasons"] == benign.REASON_CLEAR


def test_an_alert_from_a_rule_that_was_never_converted_is_refused(tmp_path):
    data, runs, population, manifest = _scenario(tmp_path)
    with (runs / "LABVM" / "alerts.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(_alert("2026-10-01 12:00:00.000 +00:00", "unknown", "LABVM")) + "\n")
    with pytest.raises(ScoreError, match="no frozen rule"):
        benign.report(data, tmp_path / "out", "ENDPOINT1", None, population=population, manifest=manifest, runs=runs)


def test_an_unknown_real_endpoint_name_is_refused(tmp_path):
    data, runs, population, manifest = _scenario(tmp_path)
    with pytest.raises(ScoreError, match="--real-endpoint"):
        benign.report(data, tmp_path / "out", "OTHERPC", None, population=population, manifest=manifest, runs=runs)
