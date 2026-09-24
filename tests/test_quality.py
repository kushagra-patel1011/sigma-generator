"""Tests for rule quality: evidence mining, quality tiers, skeletons, count-based
correlations, distinct attack-chain steps and quality reporting.

Most tests use small synthetic ATT&CK techniques built from the real data classes,
so each behaviour is pinned down independently of how ATT&CK words a technique.
"""

from __future__ import annotations

import json
import uuid

import pytest

from conftest import ATTACK_FIXTURE, SIGMAHQ_FIXTURE
from src import utils
from src.attack_fetcher import Analytic, AttackDataset, DetectionStrategy, LogSourceRef, Technique
from src.main import main
from src.mappings import resolve_telemetry
from src.packs import build_pack
from src.sigma_generator import (
    SigmaRuleGenerator,
    ThreatContext,
    assess_quality,
    is_generic,
    normalise_value,
    selection_values,
    validate_rule,
    validate_sigma_text,
    validate_with_pysigma,
)
from src.stix_builder import BundleOptions, build_bundle
from src.utils import InsufficientEvidenceError
from src.web.server import WebApp, _options_from
from src.service import Workspace


# --------------------------------------------------------------------------- #
# Synthetic ATT&CK objects
# --------------------------------------------------------------------------- #
def make_analytic(description: str, sources: list[tuple], knobs: tuple = (), platforms: tuple = ("Windows",),
                  analytic_id: str = "AN9001") -> Analytic:
    return Analytic(
        id=analytic_id,
        stix_id=f"x-mitre-analytic--{uuid.uuid4()}",
        name=analytic_id,
        description=description,
        platforms=platforms,
        log_sources=tuple(LogSourceRef(*source) for source in sources),
        mutable_elements=tuple(knobs),
    )


def make_technique(*analytics: Analytic, description: str = "", tactics: tuple = ("credential-access",),
                   platforms: tuple = ("Windows",), technique_id: str = "T9001") -> Technique:
    strategy = DetectionStrategy(
        id="DET9001", stix_id=f"x-mitre-detection-strategy--{uuid.uuid4()}", name="Test strategy",
        analytics=tuple(analytics), url="https://attack.mitre.org/detectionstrategies/DET9001",
    )
    return Technique(
        id=technique_id, stix_id=f"attack-pattern--{uuid.uuid4()}", name="Test Technique",
        description=description, url="https://attack.mitre.org/techniques/T9001",
        platforms=platforms, tactics=tactics, detection_strategies=(strategy,),
    )


@pytest.fixture()
def generator() -> SigmaRuleGenerator:
    return SigmaRuleGenerator(deterministic=True, attack_version="19.2")


@pytest.fixture(scope="module")
def dataset() -> AttackDataset:
    return AttackDataset.from_file(ATTACK_FIXTURE)


def pysigma_problems(text: str) -> list[str]:
    ran, problems = validate_with_pysigma(text)
    if not ran:
        pytest.skip("pySigma is not installed")
    return problems


# --------------------------------------------------------------------------- #
# Evidence mining
# --------------------------------------------------------------------------- #
class TestToolLexicon:
    def test_listed_tools_are_found(self):
        found = utils.extract_artefacts("Processes executing kextload, spctl, or modifying kernel extensions")
        assert found.utilities == ["kextload", "spctl"]

    @pytest.mark.parametrize("text,expected", [
        ("attackers run reg add HKCU\\Software\\Run", ["reg"]),
        ("they use sc create svc and net user admin /add", ["net", "sc"]),
        ("the security dump-keychain command", ["security"]),
        ("defaults write com.apple.loginwindow LoginHook", ["defaults"]),
        ("registry keys that weaken security settings by default", []),
        ("a net gain for the attacker; query the regional office", []),
    ])
    def test_ambiguous_names_need_a_subcommand(self, text, expected):
        assert utils.extract_artefacts(text).utilities == expected

    def test_exe_suffix_is_recognised(self):
        found = utils.extract_artefacts("downloads with certutil.exe -urlcache")
        assert "certutil" in found.utilities and "certutil.exe" in found.executables

    @pytest.mark.parametrize("text,expected", [
        ("Inbound on ports 5985/5986", [5985, 5986]),
        ("connections on TCP 445 and port 22, 3389", [445, 22, 3389]),
        ("EventCode=4624, 4648", []),
        ("port 99999", []),
    ])
    def test_ports(self, text, expected):
        assert utils.extract_artefacts(text).ports == expected

    def test_illustrative_paths_are_ignored(self):
        found = utils.extract_artefacts("drops C:\\temp\\evil.exe and C:\\Users\\Public\\payload\\run.bat into C:\\Windows\\Tasks")
        assert all("evil" not in path and "payload" not in path for path in found.paths)
        assert "C:\\Windows\\Tasks" in found.paths


class TestTelemetrySources:
    def test_repeated_log_sources_are_merged(self, generator):
        analytic = make_analytic(
            "Repeated enumeration of cloud infrastructure",
            [("AWS:CloudTrail", "DescribeInstances", "Instance Metadata"),
             ("AWS:CloudTrail", "ListBuckets", "Cloud Storage Enumeration"),
             ("AWS:CloudTrail", "DescribeDBInstances", "Instance Enumeration")],
            platforms=("IaaS",),
        )
        sources = generator.telemetry_sources(analytic, "IaaS")
        assert len(sources) == 1
        assert sources[0].mapping.base_selection["eventName"] == ["DescribeInstances", "ListBuckets", "DescribeDBInstances"]
        assert len(sources[0].channels) == 3

    def test_channel_text_is_mined_first(self, generator):
        analytic = make_analytic(
            "Detect user-initiated kernel extension loads.",
            [("macos:unifiedlog", "Processes executing kextload or spctl", "Process Creation")],
            platforms=("macOS",),
        )
        rule = generator.generate(make_technique(analytic, platforms=("macOS",)))[0]
        assert rule.logsource == {"category": "process_creation", "product": "macos"}
        assert set(rule.detection["selection_image"]["Image|endswith"]) == {"/kextload", "/spctl"}

    def test_ports_become_a_selection_on_flow_logs(self, generator):
        analytic = make_analytic("Remote management traffic.",
                                 [("NSM:Connections", "Inbound on ports 5985/5986", "Network Traffic Flow")],
                                 platforms=("Windows",))
        rule = generator.generate(make_technique(analytic))[0]
        assert rule.detection["selection_port"] == {"id.resp_p": [5985, 5986]}
        assert rule.quality.tier == "moderate"

    def test_unknown_filesystem_source_follows_the_platform(self):
        mapping = resolve_telemetry("fs:plist", "/Library/Preferences/x.plist", "Unknown Component", "macOS")
        assert mapping.logsource.as_dict() == {"category": "file_event", "product": "macos"}


# --------------------------------------------------------------------------- #
# Quality tiers
# --------------------------------------------------------------------------- #
class TestAssessQuality:
    @pytest.mark.parametrize("detection,tier", [
        ({}, "placeholder"),
        ({"selection_todo": {"CommandLine": "TODO"}, "condition": "selection_todo"}, "placeholder"),
        ({"selection_source": {"EventID": 4720}, "condition": "selection_source"}, "weak"),
        ({"selection_image": {"Image|endswith": ["\\powershell.exe", "\\cmd.exe"]}, "condition": "selection_image"}, "weak"),
        ({"selection_image": {"Image|endswith": ["\\certutil.exe"]}, "condition": "selection_image"}, "weak"),
        ({"selection_registry": {"TargetObject|contains": ["\\CurrentVersion\\Run"]}, "condition": "selection_registry"}, "moderate"),
        ({"selection_image": {"Image|endswith": ["\\certutil.exe", "\\bitsadmin.exe"]}, "condition": "selection_image"}, "moderate"),
        ({"selection_target": {"TargetImage|endswith": ["\\lsass.exe"]},
          "selection_indicator_access": {"GrantedAccess": ["0x1f0fff"]},
          "condition": "selection_target and selection_indicator_access"}, "strong"),
    ])
    def test_tiers(self, detection, tier):
        assert assess_quality(detection).tier == tier

    def test_generic_values_do_not_count_as_signals(self):
        quality = assess_quality({
            "selection_image": {"Image|endswith": ["\\powershell.exe"]},
            "selection_indicator_path": {"TargetFilename|contains": [":\\Windows\\System32"]},
            "condition": "selection_image and selection_indicator_path",
        })
        assert quality.tier == "weak" and quality.signals == 0

    def test_reasons_are_reported(self):
        quality = assess_quality({"selection_source": {"EventID": 4720}, "condition": "selection_source"})
        assert "event type" in quality.reasons[0]
        assert quality.meaning and quality.label.startswith("weak - ")


class TestSkeletonsAndWeakRules:
    def test_no_concrete_values_means_no_rule(self, generator):
        analytic = make_analytic("Detects exploitation of vulnerable drivers.", [("WinEventLog:Sysmon", "EventCode=6", "Driver Load")],
                                 knobs=(("DriverNamePattern", "Targeted drivers vary by campaign."),))
        technique = make_technique(analytic)
        with pytest.raises(InsufficientEvidenceError, match="DriverNamePattern"):
            generator.generate(technique)

    def test_skeleton_rules_are_marked_and_match_nothing(self, generator):
        analytic = make_analytic("Detects exploitation of vulnerable drivers.", [("WinEventLog:Sysmon", "EventCode=6", "Driver Load")])
        rule = generator.generate(make_technique(analytic), include_skeletons=True)[0]
        assert rule.quality.tier == "placeholder"
        assert rule.status == "unsupported" and rule.level == "informational"
        assert rule.detection["condition"] == "selection_todo"
        assert "TODO" in str(rule.detection["selection_todo"])
        assert "SKELETON RULE" in rule.to_yaml()
        assert validate_rule(utils.load_yaml(rule.to_yaml(include_banner=False))) == []
        assert pysigma_problems(rule.to_yaml(include_banner=False)) == []

    def test_false_positives_only_name_matched_tools(self, generator):
        analytic = make_analytic("mimikatz.exe changing accounts",
                                 [("WinEventLog:Security", "EventCode=4738", "User Account Modification")])
        rule = generator.generate(make_technique(analytic))[0]
        assert "selection_image" not in rule.detection
        assert not any("mimikatz" in entry for entry in rule.falsepositives)
        process = make_analytic("'certutil.exe -urlcache -f' downloads", [("WinEventLog:Sysmon", "EventCode=1", "Process Creation")])
        rule = generator.generate(make_technique(process))[0]
        assert any("use of certutil.exe" in entry for entry in rule.falsepositives)

    def test_weak_rules_are_tagged_for_hunting_and_capped(self, generator):
        analytic = make_analytic("New accounts that resemble service accounts.",
                                 [("WinEventLog:Security", "EventCode=4720", "User Account Creation")])
        rule = generator.generate(make_technique(analytic, tactics=("credential-access",)))[0]
        assert rule.quality.tier == "weak"
        assert "detection.threat-hunting" in rule.tags
        assert rule.level == "low"
        assert any("threat-hunting" in note for note in rule.provenance.notes)

    def test_deployable_candidates_beat_weak_ones(self, generator):
        weak = make_analytic("Account creation.", [("WinEventLog:Security", "EventCode=4720", "User Account Creation")],
                             analytic_id="AN0001")
        # Flags only count inside quotes, which is how ATT&CK writes real command lines.
        strong = make_analytic("certutil.exe run as 'certutil.exe -urlcache -f' or with '-decode' to fetch payloads",
                               [("WinEventLog:Sysmon", "EventCode=1", "Process Creation")], analytic_id="AN0002")
        rule = generator.generate(make_technique(weak, strong))[0]
        assert rule.provenance.analytic_id == "AN0002"
        assert rule.quality.tier in ("moderate", "strong")


# --------------------------------------------------------------------------- #
# Count-based correlation rules
# --------------------------------------------------------------------------- #
class TestCountRules:
    def test_password_spraying_becomes_a_value_count(self, generator):
        analytic = make_analytic(
            "Multiple failed logons against different accounts from a single source address.",
            [("WinEventLog:Security", "EventCode=4625", "User Account Authentication")],
        )
        rule = generator.generate_count_rules(make_technique(analytic))[0]
        correlation = rule.correlation
        assert correlation["type"] == "value_count"
        assert correlation["condition"] == {"field": "TargetUserName", "gte": 5}
        assert correlation["group-by"] == ["IpAddress"]
        assert rule.kind == "count" and "_count_" in rule.filename()
        assert any("default" in note for note in rule.provenance.notes)
        assert validate_sigma_text(rule.to_yaml()) == []
        assert pysigma_problems(rule.to_yaml(include_banner=False)) == []

    def test_stated_threshold_is_used(self, generator):
        analytic = make_analytic("Excessive authentication failures: more than 20 failed logons for one account.",
                                 [("WinEventLog:Security", "EventCode=4625", "User Account Authentication")])
        rule = generator.generate_count_rules(make_technique(analytic))[0]
        assert rule.correlation["type"] == "event_count"
        assert rule.correlation["condition"] == {"gte": 20}
        assert rule.correlation["group-by"] == ["TargetUserName"]
        assert any("stated in ATT&CK" in note for note in rule.provenance.notes)

    def test_no_volume_wording_means_no_count_rule(self, generator):
        analytic = make_analytic("New scheduled tasks created by unusual users.",
                                 [("WinEventLog:Security", "EventCode=4698", "Scheduled Job Creation")])
        assert generator.generate_count_rules(make_technique(analytic)) == []

    def test_size_thresholds_are_not_volume(self, generator):
        analytic = make_analytic("Suspicious script blocks.",
                                 [("WinEventLog:PowerShell", "EventCode=4104", "Command Execution")],
                                 knobs=(("ScriptBlockLengthThreshold", "Adjustable threshold for length of script blocks"),))
        assert generator.generate_count_rules(make_technique(analytic)) == []

    def test_specific_rules_only_get_counts_from_source_wording(self, generator):
        description = "'certutil.exe -urlcache -f' or 'bitsadmin.exe /transfer' downloads at a high rate of executions"
        specific = make_analytic(description, [("WinEventLog:Sysmon", "EventCode=1", "Process Creation")])
        assert generator.generate(make_technique(specific))[0].quality.tier != "weak"
        assert generator.generate_count_rules(make_technique(specific)) == []

        stated = make_analytic(description, [("WinEventLog:Sysmon", "EventCode=1: bursts of downloader processes",
                                              "Process Creation")])
        rules = generator.generate_count_rules(make_technique(stated))
        assert len(rules) == 1 and rules[0].correlation["type"] == "event_count"

    @pytest.mark.parametrize("text,expected", [
        ("more than 20 failed logons", 20),
        ("5 attempts within a minute", 5),
        ("1102 events were cleared", None),
        ("EventID 4624 logons", None),
        ("1 attempt", None),
    ])
    def test_parse_threshold(self, text, expected):
        assert SigmaRuleGenerator.parse_threshold(text) == expected


# --------------------------------------------------------------------------- #
# Attack-chain steps
# --------------------------------------------------------------------------- #
def step_values(step) -> set[str]:
    return {normalise_value(v) for name, block in step.detection.items()
            if name not in ("condition", "selection_source") for v in selection_values(block)}


class TestVolumeWording:
    @pytest.mark.parametrize("text,expected", [
        ("High volume of failed logon attempts followed by a successful logon", "High volume"),
        ("number of unique destination IPs or ports accessed within a window", "number of unique destination IPs"),
        ("Enumerations executed frequently or across multiple interfaces", "executed frequently"),
        ("a burst of DescribeInstances calls", "burst"),
        ("Rate/volume of read operations per session", "Rate/volume of read operations"),
        # an amount of something that is not an event count, or not an amount at all
        ("Detects python scripts from ~/Downloads/, /Volumes/, or /tmp/.", None),
        ("Detects mounting of external volumes", None),
        ("Frequently used to deceive Gatekeeper and users", None),
        ("Monitor for specific plist agents frequently abused for persistence", None),
        ("Tune time of day or frequency of capture sessions", None),
        ("Adjust to reduce noise from frequent deploys", None),
        ("unbalanced outbound traffic volume", None),
        # an amount described as normal
        ("Allowlist of high-volume, benign domains used by corporate CDNs", None),
    ])
    def test_sentences(self, text, expected):
        assert SigmaRuleGenerator.volume_phrase([text]) == expected

    @pytest.mark.parametrize("name,counts", [
        ("ScanRateThreshold", True), ("FrequencyThreshold", True), ("ArtifactCountThreshold", True),
        ("HTTP5xxRateThreshold", True), ("OutboundDataRateThreshold", False), ("PacketRateThreshold", False),
        ("DataVolumeThreshold", False), ("RareSignerThreshold", False), ("ScriptBlockLengthThreshold", False),
    ])
    def test_knob_names(self, name, counts):
        assert (SigmaRuleGenerator.volume_phrase([], [name]) == name) is counts

    def test_disk_volumes_do_not_make_count_rules(self, generator):
        analytic = make_analytic("Python scripts launched from /Volumes/ or /tmp/ by unusual parents.",
                                 [("macos:unifiedlog", "process exec", "Process Creation")], platforms=("macOS",))
        assert generator.generate_count_rules(make_technique(analytic, platforms=("macOS",))) == []


class TestGenericAlternatives:
    def test_generic_values_are_dropped_from_unanchored_lists(self, generator):
        analytic = make_analytic("Modification of /etc/passwd, /etc/group or /bin/bash by usermod",
                                 [("auditd:PATH", "name=/etc/passwd", "File Modification")], platforms=("Linux",))
        rule = generator.generate(make_technique(analytic, platforms=("Linux",)))[0]
        assert rule.detection["selection_indicator_path"] == {"name|contains": ["/etc/group", "/etc/passwd"]}
        assert any("Left out /bin/bash" in note for note in rule.provenance.notes)

    def test_generic_values_stay_when_the_rule_is_anchored(self, generator):
        analytic = make_analytic("rundll32.exe or werfault.exe opening lsass.exe with 0x1fffff",
                                 [("WinEventLog:Sysmon", "EventCode=10", "Process Access")])
        rule = generator.generate(make_technique(analytic))[0]
        assert rule.detection["selection_indicator_source"]["SourceImage|endswith"] == ["\\rundll32.exe", "\\werfault.exe"]
        assert rule.quality.tier == "strong"

    def test_all_generic_lists_are_kept_and_graded_weak(self, generator):
        analytic = make_analytic("powershell.exe and cmd.exe spawned by Office",
                                 [("WinEventLog:Sysmon", "EventCode=1", "Process Creation")])
        rule = generator.generate(make_technique(analytic))[0]
        assert rule.detection["selection_image"]["Image|endswith"] == ["\\cmd.exe", "\\powershell.exe"]
        assert rule.quality.tier == "weak"

    def test_windows_components_are_not_created_files(self, generator):
        analytic = make_analytic(
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump writes a dump; mimikatz copies "
            "C:\\Windows\\System32\\mimilib.dll for persistence",
            [("WinEventLog:Sysmon", "EventCode=11", "File Creation")],
        )
        rule = generator.generate(make_technique(analytic))[0]
        paths = rule.detection["selection_path"]["TargetFilename|contains"]
        assert paths == [":\\Windows\\System32\\mimilib.dll"]

    @pytest.mark.parametrize("value,generic", [
        ("/bin/bash", True), ("/usr/bin/python3", True), ("\\powershell.exe", True),
        (":\\Windows\\System32\\cmd.exe", True), ("/etc/passwd", False), ("/tmp/x.sh", False),
        ("\\certutil.exe", False),
    ])
    def test_is_generic(self, value, generic):
        assert is_generic(value) is generic


class TestSoftwarePlatforms:
    @pytest.fixture()
    def technique(self):
        windows = make_analytic("New accounts created", [("WinEventLog:Security", "EventCode=4720", "User Account Creation")],
                                analytic_id="AN0001")
        linux = make_analytic("'useradd -o -u 0' creating a root-equivalent user with /etc/passwd edits",
                              [("auditd:SYSCALL", "execve useradd", "Process Creation")],
                              platforms=("Linux",), analytic_id="AN0002")
        return make_technique(windows, linux, platforms=("Windows", "Linux"))

    def test_best_rule_wins_without_context(self, generator, technique):
        assert generator.generate(technique)[0].provenance.analytic_id == "AN0002"

    def test_software_platforms_restrict_the_choice(self, generator, technique):
        context = ThreatContext("Mimikatz (S0002)", platforms=("Windows",))
        rule = generator.generate(technique, context=context)[0]
        assert rule.provenance.analytic_id == "AN0001" and rule.logsource["product"] == "windows"

    def test_no_matching_platform_is_flagged(self, generator, technique):
        context = ThreatContext("Example (S9999)", platforms=("macOS",))
        rule = generator.generate(technique, context=context)[0]
        assert any("as running on macOS" in note for note in rule.provenance.notes)
        assert generator.generate_correlations(technique, context=context) == []

    def test_resolved_product_must_fit_too(self):
        macos_analytic = make_analytic("x", [("auditd:SYSCALL", "execve", "Process Creation")], platforms=("macOS",))
        context = ThreatContext("Example (S9999)", platforms=("macOS",))
        assert context.fits(macos_analytic)
        assert not context.fits(macos_analytic, "linux")
        assert context.fits(macos_analytic, "aws") and context.fits(None, "macos")

    def test_mimikatz_pack_stays_on_windows(self, dataset, generator):
        pack = build_pack(dataset, generator, dataset.get_threat("S0002"), chains=True)
        products = {rule.logsource.get("product") for entry in pack.entries for rule in entry.rules}
        assert products <= {"windows"}


class TestDistinctChainSteps:
    def test_fixture_chain_steps_never_repeat_values(self, dataset, generator):
        chain = generator.generate_chains(dataset.get_technique("T1003.001"))[0]
        seen: set[str] = set()
        for step in chain.steps:
            values = step_values(step)
            assert values and not values & seen
            seen |= values
        assert chain.quality.tier == "strong"

    def test_subject_selections_claim_their_values_first(self, generator):
        analytic = make_analytic(
            "reg.exe writes HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run entries, followed by "
            "execution of the referenced binary with '-silent'.",
            [("WinEventLog:Sysmon", "EventCode=1", "Process Creation"),
             ("WinEventLog:Sysmon", "EventCode=13", "Windows Registry Key Modification")],
        )
        chain = generator.generate_chains(make_technique(analytic, tactics=("persistence",)))[0]
        by_name = {step.name: step for step in chain.steps}
        registry = by_name["step2_registry_set"].detection
        process = by_name["step1_process_creation"].detection
        assert registry["selection_registry"]["TargetObject|contains"] == ["\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
        assert "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" not in str(process)
        assert [step.name for step in chain.steps] == ["step1_process_creation", "step2_registry_set"]

    def test_chain_needs_two_behavioural_steps(self, generator):
        analytic = make_analytic("certutil.exe -urlcache downloads",
                                 [("WinEventLog:Sysmon", "EventCode=1", "Process Creation"),
                                  ("WinEventLog:Security", "EventCode=4624", "Logon Session Creation")])
        assert generator.generate_chains(make_technique(analytic)) == []


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
class TestQualityReporting:
    COMMON = ["--data", str(ATTACK_FIXTURE), "--sigmahq", str(SIGMAHQ_FIXTURE), "--offline"]

    def test_quality_command_json(self, capsys):
        assert main(["quality", "T1003.001", "T1078.004", "T1583.001", "T1583.002", "--json", *self.COMMON]) == 0
        payload = json.loads(capsys.readouterr().out)
        grades = {row["id"]: row["grade"] for row in payload["techniques"]}
        assert grades == {"T1003.001": "strong", "T1078.004": "weak", "T1583.001": "no values", "T1583.002": "unmappable"}
        assert payload["totals"]["strong"] == 1
        correlations = {row["id"]: row["correlations"] for row in payload["techniques"]}
        assert any(c["type"] == "temporal" for c in correlations["T1003.001"])
        assert any(c["type"] == "event_count" for c in correlations["T1078.004"])

    def test_quality_command_for_a_group(self, capsys):
        assert main(["quality", "--group", "APT29", *self.COMMON]) == 0
        out = capsys.readouterr().out
        assert "techniques attributed to APT29 (G0016)" in out and "Deployable (strong + moderate)" in out

    def test_quality_command_grades_what_the_pack_contains(self, dataset, capsys):
        assert main(["quality", "--software", "S0002", "--json", *self.COMMON]) == 0
        rows = json.loads(capsys.readouterr().out)["techniques"]
        pack = build_pack(dataset, SigmaRuleGenerator(deterministic=True), dataset.get_threat("S0002"))
        pack_grades = {entry.technique_id: entry.rules[0].quality.tier for entry in pack.entries if entry.rules}
        assert {row["id"]: row["grade"] for row in rows if row["id"] in pack_grades} == pack_grades
        assert not any("linux" in row.get("logsource", "") or "macos" in row.get("logsource", "") for row in rows)

    def test_generate_reports_skipped_techniques(self, tmp_path, capsys):
        assert main(["generate", "T1583.001", "-o", str(tmp_path), *self.COMMON]) == 1
        assert "no concrete values" in capsys.readouterr().out
        assert main(["generate", "T1583.001", "--include-skeletons", "--no-stix", "-o", str(tmp_path), *self.COMMON]) == 0
        written = next((tmp_path / "sigma").glob("*.yml")).read_text(encoding="utf-8")
        assert "status: unsupported" in written and "SKELETON RULE" in written

    def test_generate_prints_the_quality_split(self, tmp_path, capsys):
        assert main(["generate", "T1003.001", "T1078.004", "--chains", "-o", str(tmp_path), *self.COMMON]) == 0
        out = capsys.readouterr().out
        assert "Quality:" in out and "strong" in out and "weak" in out

    def test_stix_indicator_carries_the_tier(self, dataset, generator):
        technique = dataset.get_technique("T1003.001")
        rules = generator.generate(technique)
        bundle = build_bundle(rules, technique, BundleOptions(deterministic=True))
        indicator = next(obj for obj in bundle["objects"] if obj["type"] == "indicator")
        assert "quality.strong" in indicator["labels"]
        assert "Rule quality: strong" in indicator["description"]

    def test_pack_reports_tiers(self, dataset, generator):
        pack = build_pack(dataset, generator, dataset.get_threat("G0016"), chains=True)
        summary = pack.to_dict()
        assert set(summary["summary"]["quality"]) == {"strong", "moderate", "weak", "placeholder"}
        rules = [rule for technique in summary["techniques"] for rule in technique["rules"]]
        assert rules and all(rule["quality"] in ("strong", "moderate", "weak") for rule in rules)

    def test_web_payload_and_options(self, tmp_path):
        app = WebApp(Workspace(data_path=str(ATTACK_FIXTURE), sigmahq_path=str(SIGMAHQ_FIXTURE), offline=True),
                     output_root=tmp_path)
        payload = app.generate({"technique": "T1078.004", "chains": True})
        assert payload["rules"][0]["quality"]["tier"] == "weak"
        count = next(chain for chain in payload["chains"] if chain["correlation_kind"] == "count")
        assert count["condition"]["gte"] >= 2
        skipped = app.generate({"technique": "T1583.001"})
        assert skipped["status"] == "insufficient" and not skipped["rules"]
        assert _options_from({"include_skeletons": True}).include_skeletons
