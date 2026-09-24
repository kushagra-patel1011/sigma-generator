"""Test suite for sigma-generator.

Everything runs offline against ``tests/fixtures/mini-attack.json`` - a trimmed
but otherwise untouched slice of MITRE ATT&CK Enterprise v19.2 covering the
cases the generator has to handle:

* ``T1059.001`` - Windows process creation, the happy path
* ``T1547.001`` - registry persistence, where log source choice matters
* ``T1003.001`` - LSASS access, where a process is the *target* not the actor
* ``T1003``     - one analytic per OS (Windows, Linux, macOS)
* ``T1078.004`` - cloud telemetry (CloudTrail)
* ``T1583.002`` - telemetry outside the defender's logs (must be refused)
* ``T1562.001`` - revoked in v19 (-> T1685) with no analytic left (platform fallback)
* ``T1105``     - rewritten to the pre-v18 shape (legacy data source strings)
* ``T1066``     - a revoked technique
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import mappings, stix_builder, utils  # noqa: E402
from src.attack_fetcher import AttackDataset  # noqa: E402
from src.main import main  # noqa: E402
from src.sigma_generator import (  # noqa: E402
    SigmaRuleGenerator,
    load_template,
    place_artefacts,
    validate_rule,
    validate_with_pysigma,
)
from src.stix_builder import (  # noqa: E402
    BundleOptions,
    build_bundle,
    merge_bundles,
    normalise_tlp,
    validate_bundle,
)
from src.utils import (  # noqa: E402
    DataUnavailableError,
    InsufficientEvidenceError,
    TechniqueNotFoundError,
    UnmappableTechniqueError,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mini-attack.json"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def dataset() -> AttackDataset:
    return AttackDataset.from_file(FIXTURE)


@pytest.fixture()
def generator(dataset: AttackDataset) -> SigmaRuleGenerator:
    return SigmaRuleGenerator(deterministic=True, attack_version=dataset.version)


def rule_for(dataset, generator, technique_id, **kwargs):
    return generator.generate(dataset.get_technique(technique_id), **kwargs)[0]


# --------------------------------------------------------------------------- #
# utils
# --------------------------------------------------------------------------- #
class TestTextHelpers:
    def test_clean_text_strips_attack_markup(self):
        raw = ("Adversaries may use <code>rundll32.exe</code> (Citation: Vendor Report 2021) "
               "as described in [the docs](https://example.test/doc).")
        cleaned = utils.clean_text(raw)
        assert "Citation" not in cleaned
        assert "<code>" not in cleaned
        assert "https://example.test/doc" not in cleaned
        assert "rundll32.exe" in cleaned and "the docs" in cleaned

    def test_clean_text_handles_none(self):
        assert utils.clean_text(None) == ""

    def test_first_sentences_limits_output(self):
        text = "One sentence here. Two sentences here. Three sentences here."
        assert utils.first_sentences(text, 2) == "One sentence here. Two sentences here."

    def test_first_sentences_ignores_abbreviations(self):
        text = "Adversaries may abuse rundll32.exe (i.e. Shared Modules) to proxy code. Second one. Third."
        assert utils.first_sentences(text, 2) == (
            "Adversaries may abuse rundll32.exe (i.e. Shared Modules) to proxy code. Second one."
        )

    def test_first_sentences_truncates_long_input(self):
        summary = utils.first_sentences("word " * 400, 2, max_chars=50)
        assert len(summary) <= 53 and summary.endswith("...")

    def test_slugify(self):
        assert utils.slugify("Registry Run Keys / Startup Folder") == "registry_run_keys_startup_folder"
        assert utils.slugify("!!!") == "rule"

    def test_load_env_reads_documented_format(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# comment\n\nexport SIGMA_TEST_AUTHOR='blue team'\nSIGMA_TEST_LEVEL=high\nbroken-line\n",
            encoding="utf-8",
        )
        monkeypatch.delenv("SIGMA_TEST_AUTHOR", raising=False)
        monkeypatch.delenv("SIGMA_TEST_LEVEL", raising=False)
        loaded = utils.load_env(env_file)
        assert loaded == {"SIGMA_TEST_AUTHOR": "blue team", "SIGMA_TEST_LEVEL": "high"}

    def test_load_env_missing_file_is_not_an_error(self, tmp_path):
        assert utils.load_env(tmp_path / "nope.env") == {}


class TestArtefactExtraction:
    TEXT = (
        "Adversaries abuse powershell.exe and rundll32.exe with '-enc' and '-NoProfile'. "
        "They add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run and then drop payloads in "
        "/etc/cron.d/task. Invoke-Expression is common, as is CreateRemoteThread()."
    )

    def test_finds_each_artefact_class(self):
        found = utils.extract_artefacts(self.TEXT)
        assert "powershell.exe" in found.executables
        assert "rundll32.exe" in found.executables
        assert "-enc" in found.flags and "-noprofile" in found.flags
        assert "Invoke-Expression" in found.cmdlets
        assert "CreateRemoteThread" in found.api_calls
        assert "/etc/cron.d/task" in found.paths
        assert found.count > 5 and bool(found) is True

    def test_registry_match_stops_at_prose(self):
        text = ("The key HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx is also "
                "available but is not created by default.")
        keys = utils.extract_artefacts(text).registry_keys
        assert keys == ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"]

    def test_registry_match_keeps_capitalised_segments(self):
        text = "Check HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders now."
        keys = utils.extract_artefacts(text).registry_keys
        assert keys[0].endswith("User Shell Folders")

    def test_empty_input(self):
        found = utils.extract_artefacts("", "")
        assert not found and found.count == 0

    def test_limit_is_respected(self):
        text = " ".join(f"tool{index}.exe" for index in range(40))
        assert len(utils.extract_artefacts(text, limit=5).executables) == 5

    def test_placeholder_names_are_ignored(self):
        found = utils.extract_artefacts("e.g. rundll32.exe exampledll.dll,Entry or file.exe and evil.exe")
        assert found.executables == ["rundll32.exe"]

    def test_access_masks(self):
        assert utils.extract_artefacts("opens a handle with 0x1F0FFF access").access_masks == ["0x1f0fff"]


class TestNormalisation:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
             "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("HKLM\\SYSTEM\\CurrentControlSet\\Services", "\\SYSTEM\\CurrentControlSet\\Services"),
            ("hku\\.DEFAULT\\Environment", "\\.DEFAULT\\Environment"),
            ("\\Software\\Classes", "\\Software\\Classes"),
        ],
    )
    def test_registry_hive_is_dropped(self, raw, expected):
        assert utils.normalise_registry_key(raw) == expected

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("C:\\Windows\\Temp", ":\\Windows\\Temp"),
            ("%APPDATA%\\Microsoft\\Windows\\Start Menu", "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu"),
            ("%TEMP%\\payload", "\\Temp\\payload"),
            ("%USERPROFILE%\\Downloads", "\\Downloads"),
            ("%UNKNOWNVAR%\\x", "\\x"),
            ("/etc/crontab", "/etc/crontab"),
        ],
    )
    def test_windows_paths_match_expanded_telemetry(self, raw, expected):
        assert utils.normalise_windows_path(raw) == expected

    def test_minimise_contains_drops_covered_values(self):
        values = ["\\CurrentVersion\\RunOnce", "\\CurrentVersion\\Run", "\\currentversion\\run", "\\Policies"]
        assert utils.minimise_contains(values) == ["\\CurrentVersion\\Run", "\\Policies"]


class TestYamlRendering:
    def test_sequences_are_indented_under_their_key(self):
        rendered = utils.dump_yaml({"references": ["https://a.test", "https://b.test"]})
        assert rendered == "references:\n    - https://a.test\n    - https://b.test\n"

    def test_backslash_values_are_quoted(self):
        rendered = utils.dump_yaml({"Image|endswith": "\\powershell.exe"})
        assert rendered.strip() == "Image|endswith: '\\powershell.exe'"

    def test_dates_stay_unquoted_like_sigmahq(self):
        assert utils.dump_yaml({"date": "2026-09-16"}).strip() == "date: 2026-09-16"

    def test_multiline_strings_use_block_scalars(self):
        rendered = utils.dump_yaml({"description": "first line\nsecond line"})
        assert rendered.startswith("description: |")
        assert utils.load_yaml(rendered)["description"].splitlines() == ["first line", "second line"]

    def test_key_order_is_preserved(self):
        rendered = utils.dump_yaml({"title": "a", "id": "b", "status": "c"})
        assert rendered.splitlines() == ["title: a", "id: b", "status: c"]

    def test_comment_block(self):
        assert utils.comment_block(["one", "", "two"]) == "# one\n#\n# two"


# --------------------------------------------------------------------------- #
# mappings
# --------------------------------------------------------------------------- #
class TestChannelParsing:
    @pytest.mark.parametrize(
        "channel,expected",
        [
            ("EventCode=1", [1]),
            ("EventCode=13, 14", [13, 14]),
            ("EventID: 4688", [4688]),
            ("4624, 4648", [4624, 4648]),
            ("log stream --predicate", []),
            (None, []),
        ],
    )
    def test_parse_event_codes(self, channel, expected):
        assert mappings.parse_event_codes(channel) == expected

    def test_parse_syscalls(self):
        assert mappings.parse_syscalls("open, write") == ["open", "write"]
        assert mappings.parse_syscalls("socket/connect") == ["socket", "connect"]
        assert mappings.parse_syscalls("EXECVE, execve") == ["execve"]
        assert mappings.parse_syscalls(None) == []

    def test_parse_api_operations(self):
        assert mappings.parse_api_operations("RunInstances") == ["RunInstances"]
        assert "UserLogin" in mappings.parse_api_operations("Operation=UserLogin")
        assert mappings.parse_api_operations(None) == []


class TestTelemetryResolution:
    @pytest.mark.parametrize(
        "name,channel,component,platform,category,product,service",
        [
            ("WinEventLog:Sysmon", "EventCode=1", "Process Creation", "Windows",
             "process_creation", "windows", None),
            ("WinEventLog:Sysmon", "EventCode=13, 14", "Windows Registry Key Modification", "Windows",
             "registry_set", "windows", None),
            ("WinEventLog:Sysmon", "EventCode=22", "Active DNS", "Windows",
             "dns_query", "windows", None),
            ("WinEventLog:Security", "EventCode=4688", "Process Creation", "Windows",
             "process_creation", "windows", None),
            ("WinEventLog:System", "EventCode=7045", "Service Creation", "Windows",
             None, "windows", "system"),
            ("auditd:SYSCALL", "execve", "Process Creation", "Linux",
             "process_creation", "linux", None),
            ("AWS:CloudTrail", "RunInstances", "Instance Creation", "IaaS",
             None, "aws", "cloudtrail"),
            ("NSM:Flow", "dns.log", "Active DNS", None, None, "zeek", "dns"),
        ],
    )
    def test_known_sources(self, name, channel, component, platform, category, product, service):
        mapping = mappings.resolve_telemetry(name, channel, component, platform)
        assert mapping.is_usable
        assert mapping.logsource.category == category
        assert mapping.logsource.product == product
        assert mapping.logsource.service == service

    def test_powershell_prefers_script_block_logging(self):
        mapping = mappings.resolve_telemetry(
            "WinEventLog:PowerShell", "EventCode=4103, 4104, 4105, 4106", "Command Execution", "Windows"
        )
        assert mapping.logsource.category == "ps_script"
        assert mapping.roles["script"] == "ScriptBlockText"

    def test_event_id_becomes_a_base_selection(self):
        mapping = mappings.resolve_telemetry(
            "WinEventLog:Security", "EventCode=4698", "Scheduled Job Creation", "Windows"
        )
        assert mapping.base_selection["EventID"] == 4698
        assert mapping.logsource.service == "security"

    def test_cloud_operation_becomes_a_base_selection(self):
        mapping = mappings.resolve_telemetry(
            "AWS:CloudTrail", "StopLogging, DeleteTrail", "Cloud Service Disable", "IaaS"
        )
        assert mapping.base_selection["eventName"] == ["StopLogging", "DeleteTrail"]

    def test_external_telemetry_is_refused(self):
        mapping = mappings.resolve_telemetry("Internet Scan", None, "Response Content", None)
        assert not mapping.is_usable
        assert mapping.confidence == mappings.CONF_NONE

    def test_unknown_name_falls_back_to_data_component(self):
        mapping = mappings.resolve_telemetry("Vendor:Unknown", "whatever", "Module Load", "Windows")
        assert mapping.logsource.category == "image_load"
        assert mapping.confidence == mappings.CONF_COMPONENT

    def test_windows_only_components_do_not_leak_to_other_platforms(self):
        """A 'User Account Authentication' on Okta is not a Windows 4624 event."""
        windows = mappings.resolve_telemetry(
            "WinEventLog:Security", "EventCode=4624", "User Account Authentication", "Windows"
        )
        saas = mappings.resolve_telemetry(
            "GCPAuditLogs:login.googleapis.com", "Failed sign-in events",
            "User Account Authentication", "SaaS",
        )
        assert windows.logsource.service == "security"
        assert saas.logsource.product == "gcp"

    def test_unknown_source_uses_the_vendor_prefix(self):
        mapping = mappings.resolve_telemetry(
            "WinEventLog:Microsoft-Windows-Shell-Core", "EventCode=9707", "Totally Unknown", "Windows"
        )
        assert mapping.logsource.product == "windows"
        assert mapping.logsource.service == "microsoft-windows-shell-core"

    def test_platform_fallback_per_platform(self):
        assert mappings.resolve_telemetry(None, None, None, "Windows").logsource.product == "windows"
        assert mappings.resolve_telemetry(None, None, None, "IaaS").logsource.service == "cloudtrail"
        assert mappings.resolve_telemetry(None, None, None, "Containers").logsource.product == "kubernetes"
        assert not mappings.resolve_telemetry(None, None, None, None).is_usable

    def test_resolution_never_raises(self):
        mapping = mappings.resolve_telemetry("", "", "", "")
        assert isinstance(mapping, mappings.TelemetryMapping)

    def test_mappings_are_not_shared_between_calls(self):
        first = mappings.resolve_telemetry("WinEventLog:Sysmon", "EventCode=1", "Process Creation", "Windows")
        first.base_selection["EventID"] = 999
        first.logsource.product = "mutated"
        second = mappings.resolve_telemetry("WinEventLog:Sysmon", "EventCode=1", "Process Creation", "Windows")
        assert second.base_selection == {}
        assert second.logsource.product == "windows"

    def test_downgrade_level(self):
        assert mappings.downgrade_level("high") == "medium"
        assert mappings.downgrade_level("informational") == "informational"
        assert mappings.downgrade_level("nonsense") == "nonsense"


# --------------------------------------------------------------------------- #
# attack_fetcher
# --------------------------------------------------------------------------- #
class TestAttackDataset:
    def test_metadata(self, dataset):
        meta = dataset.metadata()
        assert meta["version"] == "19.2"
        assert meta["technique_count"] > 10
        assert meta["analytic_count"] > 0

    def test_lookup_is_case_insensitive(self, dataset):
        assert dataset.get_technique("t1059.001").id == "T1059.001"

    def test_subtechnique_knows_its_parent(self, dataset):
        technique = dataset.get_technique("T1059.001")
        assert technique.is_subtechnique
        assert technique.parent_id == "T1059"
        assert technique.parent_name == "Command and Scripting Interpreter"
        assert technique.tactics == ("execution",)
        assert technique.platforms == ("Windows",)

    def test_detection_strategies_and_analytics_are_parsed(self, dataset):
        technique = dataset.get_technique("T1059.001")
        assert technique.has_detection_model
        strategy = technique.detection_strategies[0]
        assert strategy.id.startswith("DET")
        analytic = strategy.analytics[0]
        assert analytic.id.startswith("AN")
        assert analytic.log_sources[0].name == "WinEventLog:Sysmon"
        assert analytic.log_sources[0].channel == "EventCode=1"
        assert analytic.log_sources[0].data_component == "Process Creation"
        assert any(name == "CommandLinePattern" for name, _ in analytic.mutable_elements)
        assert technique.strategy_for(analytic) is strategy

    def test_descriptions_are_cleaned(self, dataset):
        description = dataset.get_technique("T1059.001").description
        assert "(Citation:" not in description and "<code>" not in description

    def test_mitigations_are_collected(self, dataset):
        assert dataset.get_technique("T1059.001").mitigations

    def test_legacy_technique_shape(self, dataset):
        technique = dataset.get_technique("T1105")
        assert technique.detection_strategies == ()
        assert technique.legacy_data_sources
        assert "certutil.exe" in technique.legacy_detection
        assert technique.has_detection_model

    def test_revoked_technique(self, dataset):
        technique = dataset.get_technique("T1066")
        assert technique.revoked
        assert technique.revoked_by
        followed = dataset.get_technique("T1066", follow_revoked=True)
        assert followed.id == technique.revoked_by

    def test_unknown_technique_raises(self, dataset):
        with pytest.raises(TechniqueNotFoundError):
            dataset.get_technique("T9999")

    def test_malformed_id_raises(self, dataset):
        with pytest.raises(TechniqueNotFoundError, match="not an ATT&CK technique ID"):
            dataset.get_technique("powershell")

    def test_search_ranks_exact_matches_first(self, dataset):
        assert dataset.search("T1059.001")[0].id == "T1059.001"
        assert dataset.search("powershell")[0].id == "T1059.001"
        assert dataset.search("")[0:] == []

    def test_search_skips_revoked(self, dataset):
        assert all(not t.revoked for t in dataset.search("remote file copy", limit=10))

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(DataUnavailableError):
            AttackDataset.from_file(tmp_path / "missing.json")

    def test_invalid_json_raises(self, tmp_path):
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        with pytest.raises(DataUnavailableError):
            AttackDataset.from_file(broken)

    def test_non_bundle_raises(self, tmp_path):
        empty = tmp_path / "empty.json"
        empty.write_text('{"type": "bundle", "objects": []}', encoding="utf-8")
        with pytest.raises(DataUnavailableError):
            AttackDataset.from_file(empty)

    def test_offline_load_without_cache_raises(self, tmp_path):
        with pytest.raises(DataUnavailableError, match="offline"):
            AttackDataset.load(path=tmp_path / "nothing.json", offline=True)


# --------------------------------------------------------------------------- #
# sigma_generator
# --------------------------------------------------------------------------- #
class TestRuleGeneration:
    def test_windows_process_creation_rule(self, dataset, generator):
        rule = rule_for(dataset, generator, "T1059.001")
        body = utils.load_yaml(rule.to_yaml(include_banner=False))

        assert body["logsource"] == {"category": "process_creation", "product": "windows"}
        assert body["status"] == "experimental"
        assert "PowerShell" in body["title"]
        assert set(body["tags"]) >= {"attack.execution", "attack.t1059", "attack.t1059.001"}
        assert body["references"][0].startswith("https://attack.mitre.org/techniques/T1059/001")
        assert "Image" in body["fields"]
        assert validate_rule(body) == []

    def test_detection_block_is_coherent(self, dataset, generator):
        rule = rule_for(dataset, generator, "T1059.001")
        detection = rule.detection
        identifiers = [key for key in detection if key != "condition"]
        assert identifiers, "rule must define at least one selection"
        for token in detection["condition"].replace("(", " ").replace(")", " ").split():
            if token in ("and", "or", "not", "1", "of"):
                continue
            assert token.rstrip("*") in identifiers or any(
                name.startswith(token.rstrip("*")) for name in identifiers
            )

    def test_registry_technique_prefers_registry_telemetry(self, dataset, generator):
        """ATT&CK offers both process creation and registry events for T1547.001."""
        rule = rule_for(dataset, generator, "T1547.001")
        assert rule.logsource["category"] == "registry_set"
        registry_selection = rule.detection["selection_registry"]
        values = registry_selection["TargetObject|contains"]
        assert any("CurrentVersion\\Run" in value for value in values)

    def test_registry_rule_matches_how_sysmon_spells_keys(self, dataset, generator):
        values = rule_for(dataset, generator, "T1547.001").detection["selection_registry"]["TargetObject|contains"]
        assert not any(value.upper().startswith(("HKEY_", "HKLM", "HKCU")) for value in values)

    def test_registry_rule_does_not_require_a_specific_writer(self, dataset, generator):
        """Run keys written through the API have no reg.exe - requiring it would miss them."""
        rule = rule_for(dataset, generator, "T1547.001")
        assert "selection_image" not in rule.detection
        assert "reg.exe" not in rule.detection["condition"]
        assert any("companion process_creation rule" in note for note in rule.provenance.notes)

    def test_process_access_targets_lsass(self, dataset, generator):
        rule = rule_for(dataset, generator, "T1003.001")
        detection = rule.detection
        assert rule.logsource["category"] == "process_access"
        assert detection["selection_target"] == {"TargetImage|endswith": ["\\lsass.exe"]}
        source_values = detection.get("selection_indicator_source", {}).get("SourceImage|endswith", [])
        assert "\\lsass.exe" not in source_values
        assert detection["condition"].startswith("selection_target")
        # CallTrace holds stack frames; mined cmdlets must never be matched against it.
        assert not any("CallTrace" in key for block in detection.values() if isinstance(block, dict)
                       for key in block)

    def test_cloud_technique_maps_to_cloudtrail(self, dataset, generator):
        rule = rule_for(dataset, generator, "T1078.004", platform="IaaS")
        assert rule.logsource == {"product": "aws", "service": "cloudtrail"}
        assert rule.title.endswith("Via AWS CloudTrail")

    def test_falsepositives_only_name_tools_from_the_rules_platform(self, dataset, generator):
        for technique_id in ("T1059.001", "T1547.001", "T1003.001"):
            rule = rule_for(dataset, generator, technique_id)
            text = " ".join(rule.falsepositives)
            assert "base64" not in text and "crontab" not in text

    def test_platform_override(self, dataset, generator):
        windows = rule_for(dataset, generator, "T1003.001", platform="Windows")
        assert windows.logsource["product"] == "windows"
        # ATT&CK has no Linux analytic for LSASS dumping: no concrete values, so no rule...
        with pytest.raises(InsufficientEvidenceError):
            rule_for(dataset, generator, "T1003.001", platform="Linux")
        # ...unless a skeleton is asked for, which is clearly marked as unusable as-is.
        linux = rule_for(dataset, generator, "T1003.001", platform="Linux", include_skeletons=True)
        assert linux.logsource["product"] == "linux"
        assert linux.status == "unsupported" and linux.quality.tier == "placeholder"

    def test_platform_is_chosen_by_telemetry_quality_not_alphabetically(self, dataset, generator):
        """T1562.001 lists Containers first, but Windows telemetry is the useful one."""
        technique = dataset.get_technique("T1562.001")
        rule = generator.generate(technique)[0]
        assert technique.platforms[0] == "Containers"
        assert rule.provenance.platform == "Windows"

    def test_specific_analytic_can_be_requested(self, dataset, generator):
        technique = dataset.get_technique("T1003.001")
        analytic_id = technique.analytics[0].id
        rule = generator.generate(technique, analytic_id=analytic_id)[0]
        assert rule.provenance.analytic_id == analytic_id

    def test_unknown_analytic_yields_no_rule(self, dataset, generator):
        technique = dataset.get_technique("T1003.001")
        with pytest.raises(UnmappableTechniqueError):
            generator.generate(technique, analytic_id="AN9999")

    def test_all_analytics_emits_several_rules(self, dataset, generator):
        technique = dataset.get_technique("T1003")  # Windows, Linux and macOS analytics
        rules = generator.generate(technique, all_analytics=True)
        assert len(rules) == len(technique.analytics) >= 2
        assert len({rule.id for rule in rules}) == len(rules)
        assert len({rule.logsource["product"] for rule in rules}) >= 2

    def test_default_emits_a_single_rule(self, dataset, generator):
        assert len(generator.generate(dataset.get_technique("T1003"))) == 1

    def test_max_rules_caps_output(self, dataset, generator):
        technique = dataset.get_technique("T1003")
        assert len(generator.generate(technique, all_analytics=True, max_rules=2)) == 2

    def test_external_telemetry_technique_is_refused(self, dataset, generator):
        # Acquire Infrastructure: Server - ATT&CK only cites Internet scan data.
        technique = dataset.get_technique("T1583.002")
        with pytest.raises(UnmappableTechniqueError, match="outside the defender"):
            generator.generate(technique)

    def test_legacy_technique_still_generates(self, dataset, generator):
        rule = rule_for(dataset, generator, "T1105")
        assert rule.provenance.analytic_id is None
        assert rule.logsource.get("category") or rule.logsource.get("product")
        assert validate_rule(utils.load_yaml(rule.to_yaml(include_banner=False))) == []

    def test_keyword_fallback_is_flagged(self, dataset, generator):
        """A rule with no mined artefacts must say so instead of looking precise."""
        technique = dataset.get_technique("T1562.001")
        rule = generator.generate(technique)[0]
        if "keywords" in rule.detection:
            assert rule.detection["condition"] == "keywords"
            assert any("keyword search" in note for note in rule.provenance.notes)
            assert rule.level in ("informational", "low")

    def test_level_is_derived_from_tactic(self, dataset, generator):
        credential_access = rule_for(dataset, generator, "T1003.001")
        assert credential_access.level in ("high", "medium")

    def test_level_override(self, dataset):
        generator = SigmaRuleGenerator(level="critical", deterministic=True)
        assert rule_for(dataset, generator, "T1059.001").level == "critical"

    def test_author_and_status_overrides(self, dataset):
        generator = SigmaRuleGenerator(author="blue team", status="test", deterministic=True)
        rule = rule_for(dataset, generator, "T1059.001")
        assert rule.author == "blue team" and rule.status == "test"

    def test_deterministic_ids_are_stable_and_unique(self, dataset):
        first = SigmaRuleGenerator(deterministic=True)
        second = SigmaRuleGenerator(deterministic=True)
        rule_a = rule_for(dataset, first, "T1059.001")
        rule_b = rule_for(dataset, second, "T1059.001")
        rule_c = rule_for(dataset, second, "T1547.001")
        assert rule_a.id == rule_b.id
        assert rule_a.id != rule_c.id

    def test_random_ids_differ_between_runs(self, dataset):
        generator = SigmaRuleGenerator(deterministic=False)
        assert rule_for(dataset, generator, "T1059.001").id != rule_for(dataset, generator, "T1059.001").id

    def test_banner_carries_provenance(self, dataset, generator):
        rule = rule_for(dataset, generator, "T1059.001")
        banner = rule.to_yaml(include_banner=True)
        assert "DRAFT RULE" in banner
        assert "T1059.001" in banner and "Confidence" in banner
        assert banner.splitlines()[0].startswith("#")
        assert "DRAFT RULE" not in rule.to_yaml(include_banner=False)

    def test_filename_is_descriptive(self, dataset, generator):
        assert rule_for(dataset, generator, "T1059.001").filename() == \
            "t1059_001_process_creation_powershell.yml"

    def test_generated_rules_parse_with_pysigma_when_available(self, dataset, generator):
        for technique_id in ("T1059.001", "T1547.001", "T1003.001", "T1078.004", "T1105"):
            rule = rule_for(dataset, generator, technique_id)
            ran, problems = validate_with_pysigma(rule.to_yaml(include_banner=False))
            if not ran:
                pytest.skip("pySigma is not installed")
            assert problems == [], f"{technique_id}: {problems}"


class TestArtefactPlacement:
    ARTEFACTS = utils.Artefacts(
        executables=["comsvcs.dll", "lsass.exe", "powershell.exe", "procdump.exe"],
        utilities=["base64", "certutil", "curl"],
        cmdlets=["Invoke-Mimikatz"],
        flags=["-ma"],
        registry_keys=["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        access_masks=["0x1f0fff"],
    )

    @staticmethod
    def mapping(name, channel, platform):
        return mappings.resolve_telemetry(name, channel, None, platform)

    def test_process_access_splits_actor_and_target(self):
        placed = place_artefacts(self.ARTEFACTS, self.mapping("WinEventLog:Sysmon", "EventCode=10", "Windows"))
        assert placed.targets == ["\\lsass.exe"]
        assert "\\lsass.exe" not in placed.actors and "\\procdump.exe" in placed.actors
        assert placed.access_masks == ["0x1f0fff"]

    def test_process_creation_moves_victims_and_dlls_into_the_command_line(self):
        placed = place_artefacts(self.ARTEFACTS, self.mapping("WinEventLog:Sysmon", "EventCode=1", "Windows"))
        assert placed.targets == [] and placed.libraries == []
        assert "lsass.exe" in placed.content and "comsvcs.dll" in placed.content
        assert placed.access_masks == []

    def test_common_victim_processes_do_not_become_content(self):
        artefacts = utils.Artefacts(executables=["svchost.exe", "explorer.exe", "lsass.exe"])
        placed = place_artefacts(artefacts, self.mapping("WinEventLog:Security", "EventCode=4698", "Windows"))
        assert placed.content == ["lsass.exe"]

    def test_windows_rules_only_get_windows_tools(self):
        placed = place_artefacts(self.ARTEFACTS, self.mapping("WinEventLog:Sysmon", "EventCode=1", "Windows"))
        assert "\\certutil.exe" in placed.actors and "\\curl.exe" in placed.actors
        assert not any("base64" in actor for actor in placed.actors)

    def test_linux_rules_only_get_unix_tools(self):
        placed = place_artefacts(self.ARTEFACTS, self.mapping("auditd:SYSCALL", "execve", "Linux"))
        assert placed.actors == ["/base64", "/curl"]
        assert "Invoke-Mimikatz" not in placed.content
        assert placed.registry_keys == []

    def test_cloud_rules_get_no_binaries(self):
        placed = place_artefacts(self.ARTEFACTS, self.mapping("AWS:CloudTrail", "RunInstances", "IaaS"))
        assert placed.actors == placed.targets == placed.libraries == []

    def test_module_load_uses_the_loaded_image_field(self):
        placed = place_artefacts(self.ARTEFACTS, self.mapping("WinEventLog:Sysmon", "EventCode=7", "Windows"))
        assert placed.libraries == ["\\comsvcs.dll"]

    def test_registry_keys_spill_into_command_line_without_a_registry_field(self):
        placed = place_artefacts(self.ARTEFACTS, self.mapping("WinEventLog:Sysmon", "EventCode=1", "Windows"))
        assert "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in placed.content
        assert placed.native_content  # flags and cmdlets were present too


class TestTemplate:
    def test_default_template_defines_field_order(self):
        order, defaults = load_template()
        assert order[:4] == ("title", "id", "status", "description")
        assert defaults["status"] == "experimental"

    def test_shipped_template_leaves_level_to_the_tactic(self, dataset):
        """`level` is a placeholder in the shipped template, so it must not pin rules."""
        _, defaults = load_template()
        assert "level" not in defaults
        generator = SigmaRuleGenerator(deterministic=True)
        # Credential access with strong content vs. a weak cloud-account hunting rule.
        assert rule_for(dataset, generator, "T1003.001").level == "high"
        assert rule_for(dataset, generator, "T1078.004").level == "low"

    def test_cli_level_beats_template_level(self, tmp_path, dataset):
        template = tmp_path / "pinned.yml"
        template.write_text("title: <t>\nlevel: low\nlogsource: {}\ndetection: {}\n", encoding="utf-8")
        generator = SigmaRuleGenerator(template_path=template, level="high", deterministic=True)
        assert rule_for(dataset, generator, "T1059.001").level == "high"

    def test_custom_template_changes_defaults_and_order(self, tmp_path, dataset):
        template = tmp_path / "custom.yml"
        template.write_text(
            "title: <t>\nid: <i>\nlevel: critical\nstatus: test\nlogsource: {}\n"
            "detection: {}\nfalsepositives:\n    - Known good deployment tooling\n",
            encoding="utf-8",
        )
        generator = SigmaRuleGenerator(template_path=template, deterministic=True)
        rule = rule_for(dataset, generator, "T1059.001")
        assert rule.status == "test"
        assert rule.level == "critical"
        assert "Known good deployment tooling" in rule.falsepositives
        rendered = utils.load_yaml(rule.to_yaml(include_banner=False))
        assert list(rendered)[:3] == ["title", "id", "level"]

    def test_missing_template_falls_back_to_builtin(self, tmp_path):
        order, defaults = load_template(tmp_path / "nope.yml")
        assert order[0] == "title" and defaults["status"] == "experimental"

    def test_non_mapping_template_falls_back(self, tmp_path):
        template = tmp_path / "list.yml"
        template.write_text("- not\n- a mapping\n", encoding="utf-8")
        order, defaults = load_template(template)
        assert order[0] == "title" and defaults["status"] == "experimental"
        assert "level" not in defaults


class TestRuleValidation:
    BASE = {
        "title": "Example Rule",
        "id": "1b0e3f66-0d0a-4a93-9a5e-0f3a5c6f6c11",
        "status": "experimental",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
        "level": "medium",
        "date": "2026-09-16",
        "tags": ["attack.execution", "attack.t1059.001"],
    }

    def valid(self, **overrides):
        rule = json.loads(json.dumps(self.BASE))
        rule.update(overrides)
        return rule

    def test_valid_rule_passes(self):
        assert validate_rule(self.valid()) == []

    def test_missing_required_fields(self):
        assert any("title" in error for error in validate_rule({"detection": {}, "logsource": {}}))

    def test_bad_uuid(self):
        assert any("UUID" in error for error in validate_rule(self.valid(id="not-a-uuid")))

    def test_bad_status_and_level(self):
        assert any("status" in error for error in validate_rule(self.valid(status="production")))
        assert any("level" in error for error in validate_rule(self.valid(level="severe")))

    def test_bad_date(self):
        assert any("date" in error for error in validate_rule(self.valid(date="16/09/2026")))

    def test_title_rules(self):
        assert any("period" in error for error in validate_rule(self.valid(title="Ends with a period.")))
        assert any("256" in error for error in validate_rule(self.valid(title="x" * 300)))

    def test_logsource_rules(self):
        assert any("category" in error for error in validate_rule(self.valid(logsource={})))
        assert any("unsupported" in error
                   for error in validate_rule(self.valid(logsource={"category": "x", "vendor": "y"})))

    def test_tag_format(self):
        assert any("namespace.value" in error for error in validate_rule(self.valid(tags=["execution"])))

    def test_condition_must_reference_defined_selections(self):
        broken = self.valid(detection={"selection": {"Image": "x"}, "condition": "selection and filter"})
        assert any("undefined selection 'filter'" in error for error in validate_rule(broken))

    def test_wildcard_condition_is_accepted(self):
        rule = self.valid(detection={
            "selection_a": {"Image": "x"},
            "selection_b": {"Image": "y"},
            "condition": "1 of selection_*",
        })
        assert validate_rule(rule) == []

    def test_wildcard_without_match_is_rejected(self):
        rule = self.valid(detection={"selection_a": {"Image": "x"}, "condition": "1 of filter_*"})
        assert any("no selection matches" in error for error in validate_rule(rule))

    def test_empty_selection_is_rejected(self):
        rule = self.valid(detection={"selection": {}, "condition": "selection"})
        assert any("empty" in error for error in validate_rule(rule))

    def test_missing_condition_is_rejected(self):
        assert any("condition" in error
                   for error in validate_rule(self.valid(detection={"selection": {"a": "b"}})))

    def test_non_mapping_rule(self):
        assert validate_rule(["not", "a", "rule"]) == ["rule is not a YAML mapping"]


# --------------------------------------------------------------------------- #
# stix_builder
# --------------------------------------------------------------------------- #
class TestStixBundle:
    @pytest.fixture()
    def bundle(self, dataset, generator):
        technique = dataset.get_technique("T1059.001")
        rules = generator.generate(technique)
        return build_bundle(rules, technique, BundleOptions(deterministic=True, tlp="amber"))

    def test_bundle_is_valid(self, bundle):
        assert validate_bundle(bundle) == []
        assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")

    def test_bundle_contains_the_expected_objects(self, bundle):
        types = [obj["type"] for obj in bundle["objects"]]
        assert types.count("indicator") == 1
        assert "attack-pattern" in types and "identity" in types
        assert "marking-definition" in types and "relationship" in types

    def test_indicator_carries_the_sigma_rule(self, bundle, dataset, generator):
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        rule = rule_for(dataset, generator, "T1059.001")
        assert indicator["pattern_type"] == "sigma"
        assert indicator["id"] == f"indicator--{rule.id}"
        assert indicator["pattern"].startswith("title:")
        assert "logsource" in indicator["pattern"]
        assert indicator["confidence"] == 95
        assert "sigma-rule" in indicator["labels"]

    def test_relationship_uses_the_spec_verb(self, bundle):
        relationship = next(o for o in bundle["objects"] if o["type"] == "relationship")
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        attack_pattern = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
        assert relationship["relationship_type"] == "indicates"
        assert relationship["source_ref"] == indicator["id"]
        assert relationship["target_ref"] == attack_pattern["id"]

    def test_attack_pattern_keeps_mitre_identity(self, bundle, dataset):
        technique = dataset.get_technique("T1059.001")
        attack_pattern = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
        assert attack_pattern["id"] == technique.stix_id
        assert attack_pattern["external_references"][0]["external_id"] == "T1059.001"

    def test_deterministic_bundles_are_reproducible(self, dataset, generator):
        technique = dataset.get_technique("T1059.001")
        rules = generator.generate(technique)
        options = BundleOptions(deterministic=True)
        first, second = build_bundle(rules, technique, options), build_bundle(rules, technique, options)
        assert [o["id"] for o in first["objects"]] == [o["id"] for o in second["objects"]]
        assert first["id"] == second["id"]

    def test_pattern_excludes_the_banner_by_default(self, bundle):
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert "DRAFT RULE" not in indicator["pattern"]

    def test_tlp_markings(self, dataset, generator):
        technique = dataset.get_technique("T1059.001")
        rules = generator.generate(technique)
        for tlp, expected in (("red", "TLP:RED"), ("clear", "TLP:WHITE"), ("green", "TLP:GREEN")):
            bundle = build_bundle(rules, technique, BundleOptions(tlp=tlp))
            marking = next(o for o in bundle["objects"] if o["type"] == "marking-definition")
            assert marking["name"] == expected
            assert validate_bundle(bundle) == []

    def test_invalid_tlp_raises(self):
        with pytest.raises(ValueError, match="Unknown TLP"):
            normalise_tlp("purple")

    def test_without_attack_pattern(self, dataset, generator):
        technique = dataset.get_technique("T1059.001")
        bundle = build_bundle(generator.generate(technique), technique,
                              BundleOptions(include_attack_pattern=False))
        types = [obj["type"] for obj in bundle["objects"]]
        assert "attack-pattern" not in types and "relationship" not in types
        assert validate_bundle(bundle) == []

    def test_merge_deduplicates_shared_objects(self, dataset, generator):
        first_technique = dataset.get_technique("T1059.001")
        second_technique = dataset.get_technique("T1547.001")
        options = BundleOptions(deterministic=True)
        merged = merge_bundles([
            build_bundle(generator.generate(first_technique), first_technique, options),
            build_bundle(generator.generate(second_technique), second_technique, options),
        ], deterministic=True)
        identities = [o for o in merged["objects"] if o["type"] == "identity"]
        assert len(identities) == 1
        assert len([o for o in merged["objects"] if o["type"] == "indicator"]) == 2
        assert validate_bundle(merged) == []

    def test_empty_rule_list_raises(self, dataset):
        with pytest.raises(ValueError):
            build_bundle([], dataset.get_technique("T1059.001"))


class TestStixValidation:
    def test_detects_dangling_reference(self, dataset, generator):
        technique = dataset.get_technique("T1059.001")
        bundle = build_bundle(generator.generate(technique), technique, BundleOptions())
        relationship = next(o for o in bundle["objects"] if o["type"] == "relationship")
        relationship["target_ref"] = "attack-pattern--00000000-0000-4000-8000-000000000000"
        assert any("not in the bundle" in error for error in validate_bundle(bundle))

    def test_detects_duplicate_ids(self, dataset, generator):
        technique = dataset.get_technique("T1059.001")
        bundle = build_bundle(generator.generate(technique), technique, BundleOptions())
        bundle["objects"].append(dict(bundle["objects"][-1]))
        assert any("more than once" in error for error in validate_bundle(bundle))

    def test_detects_missing_required_properties(self):
        bundle = {
            "type": "bundle",
            "id": "bundle--0f2c7a2e-9d0e-4f2b-8a2f-1b8c6f0f9a11",
            "objects": [{"type": "indicator", "id": "indicator--not-a-uuid"}],
        }
        errors = validate_bundle(bundle)
        assert any("valid UUID" in error for error in errors)
        assert any("pattern" in error for error in errors)

    def test_rejects_non_bundle(self):
        assert validate_bundle({"type": "grouping", "id": "grouping--x", "objects": []})

    def test_rejects_non_dict(self):
        assert validate_bundle("nope") == ["bundle is not a JSON object"]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
class TestCommandLine:
    def run(self, *args):
        return main(["--data", str(FIXTURE), "--offline", *args])

    def test_info(self, capsys):
        assert main(["info", "T1059.001", "--data", str(FIXTURE), "--offline"]) == 0
        out = capsys.readouterr().out
        assert "T1059.001  PowerShell" in out
        assert "process_creation/windows" in out

    def test_info_json(self, capsys):
        assert main(["info", "T1547.001", "--json", "--data", str(FIXTURE), "--offline"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["id"] == "T1547.001"
        assert payload["detection_strategies"][0]["analytics"][0]["log_sources"]

    def test_info_unknown_technique(self, capsys):
        assert main(["info", "T4242", "--data", str(FIXTURE), "--offline"]) == 1

    def test_search(self, capsys):
        assert main(["search", "credential", "dumping", "--data", str(FIXTURE), "--offline"]) == 0
        assert "T1003" in capsys.readouterr().out

    def test_search_without_results(self, capsys):
        assert main(["search", "zzzznotathing", "--data", str(FIXTURE), "--offline"]) == 1

    def test_generate_writes_files(self, tmp_path, capsys):
        code = main([
            "generate", "T1059.001", "T1547.001",
            "--data", str(FIXTURE), "--offline", "--deterministic",
            "--output-dir", str(tmp_path),
        ])
        assert code == 0
        rules = sorted((tmp_path / "sigma").glob("*.yml"))
        bundles = sorted((tmp_path / "stix").glob("*.json"))
        assert len(rules) == 2 and len(bundles) == 2
        assert validate_rule(utils.load_yaml(rules[0].read_text(encoding="utf-8"))) == []
        assert validate_bundle(json.loads(bundles[0].read_text(encoding="utf-8"))) == []
        assert "Wrote 2 Sigma rule(s)" in capsys.readouterr().out

    def test_generate_is_byte_identical_when_deterministic(self, tmp_path):
        for run in ("a", "b"):
            main(["generate", "T1059.001", "--data", str(FIXTURE), "--offline",
                  "--deterministic", "--output-dir", str(tmp_path / run)])
        first = next((tmp_path / "a" / "sigma").glob("*.yml")).read_text(encoding="utf-8")
        second = next((tmp_path / "b" / "sigma").glob("*.yml")).read_text(encoding="utf-8")
        assert first == second

    def test_generate_to_stdout(self, tmp_path, capsys):
        assert main(["generate", "T1059.001", "--data", str(FIXTURE), "--offline",
                     "--stdout", "--no-stix", "--deterministic"]) == 0
        out = capsys.readouterr().out
        assert "title: Potential PowerShell" in out
        assert not list(tmp_path.glob("**/*.yml"))

    def test_generate_without_banner(self, capsys):
        main(["generate", "T1059.001", "--data", str(FIXTURE), "--offline",
              "--stdout", "--no-stix", "--no-banner"])
        assert "DRAFT RULE" not in capsys.readouterr().out

    def test_generate_merged_bundle(self, tmp_path):
        main(["generate", "T1059.001", "T1547.001", "--data", str(FIXTURE), "--offline",
              "--merge-stix", "--no-sigma", "--deterministic", "--output-dir", str(tmp_path)])
        bundles = list((tmp_path / "stix").glob("*.json"))
        assert len(bundles) == 1
        payload = json.loads(bundles[0].read_text(encoding="utf-8"))
        assert len([o for o in payload["objects"] if o["type"] == "indicator"]) == 2

    def test_generate_from_file(self, tmp_path):
        id_file = tmp_path / "ids.txt"
        id_file.write_text("# techniques\nT1059.001\nT1547.001  # persistence\n", encoding="utf-8")
        assert main(["generate", "--from-file", str(id_file), "--data", str(FIXTURE),
                     "--offline", "--no-stix", "--output-dir", str(tmp_path)]) == 0
        assert len(list((tmp_path / "sigma").glob("*.yml"))) == 2

    def test_generate_reports_unmappable_techniques(self, tmp_path, capsys):
        code = main(["generate", "T1583.002", "--data", str(FIXTURE), "--offline",
                     "--output-dir", str(tmp_path)])
        assert code == 1
        assert "produced no rule" in capsys.readouterr().out

    def test_generate_follows_revoked_techniques(self, dataset, tmp_path, capsys):
        replacement = dataset.get_technique("T1066").revoked_by
        # The replacement has no concrete values in the fixture, so ask for a skeleton.
        assert main(["generate", "T1066", "--data", str(FIXTURE), "--offline", "--no-stix", "--include-skeletons",
                     "--deterministic", "--output-dir", str(tmp_path)]) == 0
        written = [path.name for path in (tmp_path / "sigma").glob("*.yml")]
        assert written and all(name.startswith(replacement.lower().replace(".", "_")) for name in written)

    def test_generate_can_keep_revoked_ids(self, tmp_path):
        assert main(["generate", "T1066", "--keep-revoked", "--include-skeletons", "--data", str(FIXTURE),
                     "--offline", "--no-stix", "--deterministic", "--output-dir", str(tmp_path)]) == 0
        assert all(path.name.startswith("t1066") for path in (tmp_path / "sigma").glob("*.yml"))

    def test_generate_without_ids_fails(self):
        assert main(["generate", "--data", str(FIXTURE), "--offline"]) == 1

    def test_generate_deduplicates_repeated_ids(self, tmp_path):
        main(["generate", "T1059.001", "t1059.001", "--data", str(FIXTURE), "--offline",
              "--no-stix", "--deterministic", "--output-dir", str(tmp_path)])
        assert len(list((tmp_path / "sigma").glob("*.yml"))) == 1

    def test_validate_command(self, tmp_path, capsys):
        main(["generate", "T1059.001", "--data", str(FIXTURE), "--offline",
              "--deterministic", "--output-dir", str(tmp_path)])
        assert main(["validate", str(tmp_path)]) == 0
        assert "file(s) valid" in capsys.readouterr().out

    def test_validate_reports_broken_files(self, tmp_path, capsys):
        broken = tmp_path / "broken.yml"
        broken.write_text("title: No logsource here\ndetection:\n    condition: selection\n", encoding="utf-8")
        assert main(["validate", str(broken)]) == 3
        assert "FAIL" in capsys.readouterr().out

    def test_validate_without_files(self, tmp_path):
        assert main(["validate", str(tmp_path / "nothing")]) == 1

    def test_update_refuses_offline(self):
        assert main(["update", "--offline"]) == 1
