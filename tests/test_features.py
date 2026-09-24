"""Tests for the differentiating features: threat packs, SigmaHQ gap analysis,
attack-chain correlation rules, the shared service layer and the web UI.

Fixtures (see conftest.py):

* ``mini-attack.json``         - ATT&CK v19.2 slice incl. APT29 (G0016),
  Mimikatz (S0002) and the SolarWinds Compromise campaign (C0024)
* ``mini-sigmahq-index.json``  - real SigmaHQ r2026-07-01 index entries for the
  fixture's techniques
"""

from __future__ import annotations

import io
import json
import threading
import urllib.error
import urllib.request
import zipfile

import pytest

from conftest import ATTACK_FIXTURE, SIGMAHQ_FIXTURE
from src import utils
from src.attack_fetcher import AttackDataset
from src.main import main
from src.mappings import resolve_telemetry
from src.packs import (
    STATUS_GENERATED,
    STATUS_INSUFFICIENT,
    STATUS_UNMAPPABLE,
    build_pack,
    render_pack_files,
    write_pack,
)
from src.service import GenerateOptions, Workspace
from src.sigma_generator import (
    ChainRule,
    SigmaRuleGenerator,
    ThreatContext,
    validate_correlation,
    validate_sigma_text,
    validate_with_pysigma,
)
from src.sigmahq import SigmaHQIndex, SigmaHQRule, assess_coverage, parse_rule_document, rule_covers
from src.stix_builder import BundleOptions, build_bundle, build_pack_bundle, validate_bundle
from src.utils import DataUnavailableError, FullyCoveredError, SigmaGeneratorError, ThreatNotFoundError
from src.web.server import ApiError, WebApp, _options_from, create_server


@pytest.fixture(scope="session")
def dataset() -> AttackDataset:
    return AttackDataset.from_file(ATTACK_FIXTURE)


@pytest.fixture(scope="session")
def index() -> SigmaHQIndex:
    return SigmaHQIndex.from_file(SIGMAHQ_FIXTURE)


@pytest.fixture()
def generator(dataset) -> SigmaRuleGenerator:
    return SigmaRuleGenerator(deterministic=True, attack_version=dataset.version)


def pysigma_or_skip(text: str) -> list[str]:
    ran, problems = validate_with_pysigma(text)
    if not ran:
        pytest.skip("pySigma is not installed")
    return problems


# --------------------------------------------------------------------------- #
# Threat profiles
# --------------------------------------------------------------------------- #
class TestThreatProfiles:
    @pytest.mark.parametrize("query", ["APT29", "apt29", "G0016", "g0016", "Cozy Bear", "NOBELIUM"])
    def test_group_resolves_by_id_name_or_alias(self, dataset, query):
        profile = dataset.get_threat(query)
        assert (profile.id, profile.kind, profile.stix_type) == ("G0016", "group", "intrusion-set")

    def test_software_and_campaign(self, dataset):
        mimikatz = dataset.get_threat("mimikatz", "software")
        assert mimikatz.id == "S0002" and mimikatz.kind == "software"
        campaign = dataset.get_threat("C0024")
        assert campaign.kind == "campaign" and campaign.name == "SolarWinds Compromise"

    def test_procedures_are_cleaned_and_linked_to_techniques(self, dataset):
        profile = dataset.get_threat("G0016")
        assert "T1059.001" in profile.technique_ids
        procedure = profile.procedures_for("T1059.001")[0]
        assert procedure.description and "(Citation:" not in procedure.description
        assert "[APT29]" not in procedure.description
        assert procedure.relationship_id.startswith("relationship--")

    def test_campaign_techniques_are_opt_in(self, dataset):
        direct = dataset.get_threat("G0016")
        combined = dataset.get_threat("G0016", with_campaigns=True)
        assert direct.campaigns == ("C0024",)
        assert not any(p.via for p in direct.procedures)
        inherited = [p for p in combined.procedures if p.via]
        assert inherited and all(p.via == "C0024" for p in inherited)
        assert set(direct.technique_ids) <= set(combined.technique_ids)

    def test_sigma_tags(self, dataset):
        assert dataset.get_threat("G0016").sigma_tag == "attack.g0016"
        assert dataset.get_threat("S0002").sigma_tag == "attack.s0002"
        assert dataset.get_threat("C0024").sigma_tag is None  # Sigma has no campaign tag namespace

    def test_kind_mismatch_is_rejected(self, dataset):
        with pytest.raises(ThreatNotFoundError, match="software ID, not a group"):
            dataset.get_threat("S0002", "group")

    def test_unknown_name_offers_suggestions(self, dataset):
        with pytest.raises(ThreatNotFoundError, match="Did you mean: APT29"):
            dataset.get_threat("APT2", "group")

    def test_search_threats(self, dataset):
        assert dataset.search_threats("cozy")[0].id == "G0016"
        assert [p.id for p in dataset.search_threats("mimi", "software")] == ["S0002"]
        assert dataset.search_threats("") == []


# --------------------------------------------------------------------------- #
# SigmaHQ index and coverage
# --------------------------------------------------------------------------- #
RULE_A = """
title: Test process rule
id: 11111111-1111-4111-8111-111111111111
status: test
level: high
tags: [attack.execution, attack.t1059.001]
logsource: {category: process_creation, product: windows}
detection:
    selection: {Image|endswith: '\\\\powershell.exe'}
    condition: selection
"""
RULE_B = """
title: Test security rule
id: 22222222-2222-4222-8222-222222222222
status: experimental
tags: [attack.t1003.001]
logsource: {product: windows, service: security}
detection:
    selection: {EventID: [4656, 4663]}
    condition: selection
"""
RULE_DEPRECATED = RULE_A.replace("status: test", "status: deprecated").replace("1111", "3333")
RULE_UNTAGGED = RULE_A.replace("tags: [attack.execution, attack.t1059.001]", "tags: [detection.threat-hunting]")


class TestSigmaHQIndex:
    def test_fixture_index_loads(self, index):
        assert index.release == "r2026-07-01"
        assert index.rules_for("t1003.001")
        assert all("T1003.001" in rule.techniques for rule in index.rules_for("T1003.001"))

    def test_related_rules_include_parent_but_not_siblings(self, index):
        related = index.related_rules("T1003.001")
        exact_ids = {rule.id for rule in index.rules_for("T1003.001")}
        assert related and not exact_ids & {rule.id for rule in related}
        for rule in related:
            assert "T1003" in rule.techniques or any(t.startswith("T1003.001.") for t in rule.techniques)

    def test_parse_rule_document(self):
        rule = parse_rule_document(utils.load_yaml(RULE_B), "rules/windows/builtin/test.yml")
        assert rule.techniques == ("T1003.001",)
        assert rule.event_ids == (4656, 4663)
        assert rule.service == "security" and rule.category is None
        assert parse_rule_document(utils.load_yaml(RULE_DEPRECATED), "rules/x.yml") is None
        assert parse_rule_document(utils.load_yaml(RULE_UNTAGGED), "rules/x.yml") is None
        assert parse_rule_document({"correlation": {}, "tags": ["attack.t1059"]}, "x.yml") is None

    def test_build_from_zip_and_round_trip(self, tmp_path):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("rules/a.yml", RULE_A)
            archive.writestr("rules/b.yml", RULE_B)
            archive.writestr("rules/deprecated/c.yml", RULE_DEPRECATED)
            archive.writestr("README.md", "not a rule")
        built = SigmaHQIndex.build_from_zip(buffer.getvalue(), release="r-test")
        assert len(built.rules) == 2 and built.total_rules == 3
        loaded = SigmaHQIndex.from_file(built.save(tmp_path / "index.json"))
        assert loaded.release == "r-test"
        assert [r.id for r in loaded.rules_for("T1059.001")] == ["11111111-1111-4111-8111-111111111111"]

    def test_empty_zip_is_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("README.md", "nothing")
        with pytest.raises(DataUnavailableError):
            SigmaHQIndex.build_from_zip(buffer.getvalue())

    def test_offline_without_index_fails_clearly(self, tmp_path):
        with pytest.raises(DataUnavailableError, match="update --sigmahq-only"):
            SigmaHQIndex.load(tmp_path / "missing.json", offline=True)

    def test_incompatible_index_format(self, tmp_path):
        path = tmp_path / "old.json"
        path.write_text('{"format": 0, "rules": []}', encoding="utf-8")
        with pytest.raises(DataUnavailableError, match="different version"):
            SigmaHQIndex.from_file(path)


class TestCoverage:
    @staticmethod
    def rule(**kwargs) -> SigmaHQRule:
        return SigmaHQRule(id="x", title="x", path="x.yml", **kwargs)

    def test_category_rules_cover_matching_telemetry(self):
        mapping = resolve_telemetry("WinEventLog:Sysmon", "EventCode=1", "Process Creation", "Windows")
        assert rule_covers(self.rule(category="process_creation", product="windows"), mapping)
        assert rule_covers(self.rule(category="process_creation"), mapping)
        assert not rule_covers(self.rule(category="process_creation", product="linux"), mapping)
        assert not rule_covers(self.rule(category="file_event", product="windows"), mapping)

    def test_registry_event_is_an_umbrella_category(self):
        mapping = resolve_telemetry("WinEventLog:Sysmon", "EventCode=13", "Windows Registry Key Modification", "Windows")
        assert rule_covers(self.rule(category="registry_event", product="windows"), mapping)
        assert not rule_covers(self.rule(category="registry_add", product="windows"), mapping)

    def test_service_rules_need_overlapping_event_ids(self):
        mapping = resolve_telemetry("WinEventLog:Security", "EventCode=4698", "Scheduled Job Creation", "Windows")
        assert rule_covers(self.rule(product="windows", service="security", event_ids=(4698, 4702)), mapping)
        assert not rule_covers(self.rule(product="windows", service="security", event_ids=(4624,)), mapping)
        assert rule_covers(self.rule(product="windows", service="security"), mapping)
        assert not rule_covers(self.rule(product="windows", service="system", event_ids=(4698,)), mapping)

    def test_assess_coverage(self, dataset, index):
        report = assess_coverage(dataset.get_technique("T1003.001"), index)
        assert report.status == "partial"
        assert report.exact_rules and report.gaps and report.covered_sources
        assert 0 < report.coverage_ratio < 1
        payload = report.to_dict()
        assert payload["status"] == "partial"
        assert len(payload["gaps"]) == len(report.gaps)
        for gap in report.gaps:
            assert gap.usable and not gap.covered
            assert not report.is_covered(gap.mapping)

    def test_unmappable_technique_status(self, dataset, index):
        assert assess_coverage(dataset.get_technique("T1583.001"), index).status in ("unmappable", "no-rules", "gap")


# --------------------------------------------------------------------------- #
# Actor context and gaps-only generation
# --------------------------------------------------------------------------- #
class TestContextAndGaps:
    def test_threat_context_shapes_the_rule(self, dataset, generator):
        profile = dataset.get_threat("G0016")
        technique = dataset.get_technique("T1059.001")
        context = ThreatContext(profile.label, profile.url, profile.sigma_tag,
                                tuple(p.description for p in profile.procedures_for(technique.id)))
        plain = generator.generate(technique)[0]
        actor = generator.generate(technique, context=context)[0]
        assert "attack.g0016" in actor.tags and "attack.g0016" not in plain.tags
        assert profile.url in actor.references
        assert "Observed use by APT29 (G0016)" in actor.description
        assert "Threat context: APT29 (G0016)" in actor.to_yaml()
        assert actor.id != plain.id

    def test_skip_mapping_excludes_telemetry(self, dataset, generator):
        technique = dataset.get_technique("T1003.001")
        best = generator.generate(technique)[0]
        other = generator.generate(
            technique, skip_mapping=lambda m: m.logsource.describe() == best.provenance.logsource_label
        )[0]
        assert other.provenance.logsource_label != best.provenance.logsource_label

    def test_everything_covered_raises_fully_covered(self, dataset, generator):
        with pytest.raises(FullyCoveredError, match="no gap to fill"):
            generator.generate(dataset.get_technique("T1059.001"), skip_mapping=lambda mapping: True)

    def test_unmappable_is_not_reported_as_covered(self, dataset, generator):
        """A technique with no Sigma-expressible telemetry must not claim SigmaHQ covers it."""
        from src.utils import UnmappableTechniqueError

        with pytest.raises(UnmappableTechniqueError):
            generator.generate(dataset.get_technique("T1583.002"), skip_mapping=lambda mapping: True)

    def test_gap_rules_use_uncovered_telemetry(self, dataset, index, generator):
        technique = dataset.get_technique("T1003.001")
        report = assess_coverage(technique, index)
        rule = generator.generate(technique, skip_mapping=report.is_covered)[0]
        assert rule.provenance.logsource_label in {gap.mapping.logsource.describe() for gap in report.gaps}


# --------------------------------------------------------------------------- #
# Attack-chain correlation rules
# --------------------------------------------------------------------------- #
class TestChains:
    @pytest.fixture()
    def chain(self, dataset, generator) -> ChainRule:
        chains = generator.generate_chains(dataset.get_technique("T1003.001"))
        assert chains, "T1003.001's analytic names several log sources"
        return chains[0]

    def test_correlation_block(self, chain):
        correlation = chain.correlation
        assert correlation["type"] == "temporal"
        assert correlation["rules"] == [step.name for step in chain.steps]
        assert len(chain.steps) >= 2
        assert correlation["group-by"] == ["Computer"]

    def test_timespan_comes_from_attack(self, chain):
        assert chain.correlation["timespan"] == "5m"
        assert any("comes from ATT&CK" in note for note in chain.provenance.notes)

    def test_file_is_valid_sigma(self, chain):
        text = chain.to_yaml()
        assert validate_sigma_text(text) == []
        assert pysigma_or_skip(chain.to_yaml(include_banner=False)) == []

    def test_multi_document_layout_follows_the_spec(self, chain):
        documents = [doc for doc in utils.load_all_yaml(chain.to_yaml()) if doc]
        assert "correlation" in documents[0]
        assert len(documents) == 1 + len(chain.steps)
        for document in documents[1:]:
            assert set(document) == {"title", "id", "name", "logsource", "detection"}

    def test_filename_follows_the_spec(self, chain):
        name = chain.filename()
        assert name.startswith("mr_t1003_001_") and name.endswith(".yml")
        assert len(name) <= 70 and name == name.lower()

    def test_level_is_raised_for_the_correlation(self, dataset, generator, chain):
        from src.mappings import LEVEL_ORDER

        single = generator.generate(dataset.get_technique("T1003.001"))[0]
        assert LEVEL_ORDER.index(chain.level) >= LEVEL_ORDER.index(single.level)

    def test_steps_are_behavioural(self, chain):
        for step in chain.steps:
            assert step.detection["condition"] not in ("selection_source", "keywords")

    def test_no_chain_without_two_behavioural_steps(self, dataset, generator):
        assert generator.generate_chains(dataset.get_technique("T1621")) == []

    def test_deterministic_ids(self, dataset):
        first = SigmaRuleGenerator(deterministic=True).generate_chains(dataset.get_technique("T1003.001"))[0]
        second = SigmaRuleGenerator(deterministic=True).generate_chains(dataset.get_technique("T1003.001"))[0]
        assert first.id == second.id
        assert [s.id for s in first.steps] == [s.id for s in second.steps]
        assert len({first.id, *[s.id for s in first.steps]}) == 1 + len(first.steps)

    @pytest.mark.parametrize("texts,expected", [
        (["Defines time between access and dump (e.g., 5 minutes)."], "5m"),
        (["within 5-10 seconds"], "10s"),
        (["Correlation window (e.g., 5–15 minutes)"], "15m"),
        (["over roughly 2 hours"], "2h"),
        (["a 5 min window"], "5m"),
        (["Trigger on excessive backdating (e.g., >90 days)"], None),
        (["no duration here"], None),
    ])
    def test_parse_timespan(self, texts, expected):
        parsed = SigmaRuleGenerator.parse_timespan(texts)
        assert (parsed[0] if parsed else None) == expected

    def test_chain_in_stix_bundle(self, dataset, generator, chain):
        technique = dataset.get_technique("T1003.001")
        rules = generator.generate(technique)
        bundle = build_bundle(rules, technique, BundleOptions(deterministic=True), chains=[chain])
        assert validate_bundle(bundle) == []
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        chain_indicator = next(o for o in indicators if o["id"] == f"indicator--{chain.id}")
        assert "sigma-correlation-rule" in chain_indicator["labels"]
        assert "correlation:" in chain_indicator["pattern"] and "---" in chain_indicator["pattern"]


class TestCorrelationValidation:
    VALID = {
        "title": "Failed logins followed by success",
        "id": "b180ead8-d58f-40b2-ae54-c8940995b9b6",
        "correlation": {"type": "temporal_ordered", "rules": ["failed", "success"],
                        "group-by": ["User"], "timespan": "10m"},
    }

    def check(self, **correlation_overrides):
        rule = json.loads(json.dumps(self.VALID))
        rule["correlation"].update(correlation_overrides)
        return validate_correlation(rule, {"failed", "success"})

    def test_valid_rule(self):
        assert self.check() == []

    def test_unknown_reference(self):
        assert any("not defined in this file" in e for e in self.check(rules=["failed", "ghost"]))

    def test_uuid_references_may_live_elsewhere(self):
        assert self.check(rules=["failed", "5638f7c0-ac70-491d-8465-2a65075e0d86"]) == []

    def test_timespan_format(self):
        assert any("timespan" in e for e in self.check(timespan="10 minutes"))

    def test_group_by_required(self):
        assert any("group-by" in e for e in self.check(**{"group-by": []}))

    def test_temporal_needs_two_rules(self):
        assert any("at least two" in e for e in self.check(rules=["failed"]))

    def test_counting_types_need_a_condition(self):
        assert any("condition" in e for e in self.check(type="event_count", rules=["failed"]))
        assert self.check(type="event_count", rules=["failed"], condition={"gte": 10}) == []
        assert any("field" in e for e in self.check(type="value_count", rules=["failed"], condition={"gte": 3}))

    def test_bad_type_and_aliases(self):
        assert any("correlation type" in e for e in self.check(type="sequence"))
        assert any("unknown rule" in e for e in self.check(aliases={"host": {"nobody": "Computer"}}))

    def test_sigma_text_edge_cases(self):
        assert validate_sigma_text("") == ["file contains no YAML documents"]
        assert validate_sigma_text("title: [unclosed")[0].startswith("not valid YAML")
        duplicate = "title: a\nname: x\nlogsource: {product: windows}\ndetection: {s: {a: b}, condition: s}\n"
        assert any("unique" in e for e in validate_sigma_text(duplicate + "---\n" + duplicate))


# --------------------------------------------------------------------------- #
# Detection packs
# --------------------------------------------------------------------------- #
class TestPacks:
    @pytest.fixture()
    def pack(self, dataset, generator, index):
        return build_pack(dataset, generator, dataset.get_threat("G0016"), chains=True, sigmahq=index)

    def test_every_attributed_technique_has_an_entry(self, dataset, pack):
        profile = dataset.get_threat("G0016")
        assert sorted(e.technique_id for e in pack.entries) == sorted(profile.technique_ids)
        assert pack.rule_count > 0 and pack.chain_count > 0
        assert {e.status for e in pack.entries} <= {STATUS_GENERATED, STATUS_INSUFFICIENT, STATUS_UNMAPPABLE}

    def test_rules_carry_actor_context(self, pack):
        rule = next(e for e in pack.entries if e.rules).rules[0]
        assert "attack.g0016" in rule.tags
        assert rule.provenance.threat_label == "APT29 (G0016)"

    def test_summary_and_markdown(self, pack):
        summary = pack.to_dict()["summary"]
        assert summary["techniques"] == len(pack.entries)
        assert summary["rules"] == pack.rule_count
        markdown = pack.to_markdown()
        assert markdown.startswith("# Detection pack: APT29 (G0016)")
        assert "| Technique | Tactics | Rules | Correlations | SigmaHQ | Status |" in markdown
        assert "| Quality: strong / moderate / weak |" in markdown
        assert sum(summary["quality"].values()) == pack.rule_count + pack.chain_count
        assert "Techniques SigmaHQ has no rule for" in markdown

    def test_gaps_only_requires_the_index(self, dataset, generator):
        with pytest.raises(SigmaGeneratorError, match="SigmaHQ index"):
            build_pack(dataset, generator, dataset.get_threat("G0016"), gaps_only=True)

    def test_gaps_only_pack(self, dataset, generator, index):
        pack = build_pack(dataset, generator, dataset.get_threat("G0016"), sigmahq=index, gaps_only=True)
        assert pack.gaps_only and pack.rule_count > 0
        for entry in pack.entries:
            for rule in entry.rules:
                label = rule.provenance.logsource_label
                if entry.coverage.usable_sources:
                    # Analytic-backed technique: the rule targets one of the reported gaps.
                    assert label in {g.mapping.logsource.describe() for g in entry.coverage.gaps}
                else:
                    # No ATT&CK analytic (platform fallback): no SigmaHQ rule may watch that telemetry.
                    assert label not in {r.logsource_label for r in entry.coverage.exact_rules}

    def test_written_pack_is_valid(self, dataset, pack, tmp_path):
        written = write_pack(pack, tmp_path, dataset, BundleOptions(deterministic=True))
        folder = written["folder"]
        assert (folder / "README.md").is_file() and (folder / "pack.json").is_file()
        assert written["bundle_errors"] == []
        rule_files = sorted((folder / "sigma").glob("*.yml"))
        assert len(rule_files) == pack.rule_count + pack.chain_count
        assert any(path.name.startswith("mr_") for path in rule_files)
        for path in rule_files:
            assert validate_sigma_text(path.read_text(encoding="utf-8")) == [], path.name

        bundle = json.loads(written["bundle"].read_text(encoding="utf-8"))
        assert validate_bundle(bundle) == []
        by_type = {}
        for obj in bundle["objects"]:
            by_type.setdefault(obj["type"], []).append(obj)
        assert by_type["intrusion-set"][0]["id"] == dataset.get_threat("G0016").stix_id
        report = by_type["report"][0]
        assert report["name"] == "Detection pack: APT29 (G0016)"
        assert set(report["object_refs"]) <= {obj["id"] for obj in bundle["objects"]}
        uses = [r for r in by_type["relationship"] if r["relationship_type"] == "uses"]
        assert uses and all(r["description"] for r in uses)
        assert len(by_type["indicator"]) == pack.rule_count + pack.chain_count

    def test_render_matches_write(self, dataset, pack, tmp_path):
        files, errors = render_pack_files(pack, dataset, BundleOptions(deterministic=True))
        assert errors == []
        assert "README.md" in files and "pack.json" in files
        assert sum(1 for path in files if path.startswith("sigma/")) == pack.rule_count + pack.chain_count

    def test_software_and_campaign_bundles(self, dataset, generator):
        for query, stix_type in (("S0002", "tool"), ("C0024", "campaign")):
            profile = dataset.get_threat(query)
            pack = build_pack(dataset, generator, profile)
            bundle = build_pack_bundle(profile, [(e.technique, e.rules, e.chains) for e in pack.generated],
                                       dataset, BundleOptions())
            assert validate_bundle(bundle) == []
            assert any(obj["type"] == stix_type and obj["id"] == profile.stix_id for obj in bundle["objects"])

    def test_malware_requires_is_family(self):
        bundle = {"type": "bundle", "id": "bundle--0f2c7a2e-9d0e-4f2b-8a2f-1b8c6f0f9a11", "objects": [{
            "type": "malware", "spec_version": "2.1", "id": "malware--0f2c7a2e-9d0e-4f2b-8a2f-1b8c6f0f9a12",
            "created": "2020-01-01T00:00:00.000Z", "modified": "2020-01-01T00:00:00.000Z", "name": "x",
        }]}
        assert any("is_family" in error for error in validate_bundle(bundle))


# --------------------------------------------------------------------------- #
# Service layer
# --------------------------------------------------------------------------- #
class TestService:
    @pytest.fixture()
    def workspace(self):
        return Workspace(data_path=str(ATTACK_FIXTURE), sigmahq_path=str(SIGMAHQ_FIXTURE), offline=True)

    def test_generate_technique_with_chains_and_coverage(self, workspace):
        result = workspace.generate_technique("T1003.001", GenerateOptions(chains=True, deterministic=True))
        assert result.ok and result.rules and result.chains
        assert result.coverage is not None and result.coverage.status == "partial"
        assert result.problems == {}
        assert validate_bundle(result.bundle) == []

    def test_follows_revocation(self, workspace, dataset):
        replacement = dataset.get_technique("T1066").revoked_by
        result = workspace.generate_technique("T1066", GenerateOptions())
        assert result.technique.id == replacement
        assert any("revoked" in warning for warning in result.warnings)

    def test_errors_are_reported_not_raised(self, workspace):
        result = workspace.generate_technique("T9999", GenerateOptions())
        assert result.status == "error" and not result.ok

    def test_no_surprise_download_without_gap_request(self, tmp_path):
        workspace = Workspace(data_path=str(ATTACK_FIXTURE), sigmahq_path=str(tmp_path / "none.json"), offline=False)
        result = workspace.generate_technique("T1059.001", GenerateOptions(), with_bundle=False)
        assert result.ok and result.coverage is None

    def test_gaps_only_without_index_offline_fails(self, tmp_path):
        workspace = Workspace(data_path=str(ATTACK_FIXTURE), sigmahq_path=str(tmp_path / "none.json"), offline=True)
        with pytest.raises(DataUnavailableError):
            workspace.generate_technique("T1059.001", GenerateOptions(gaps_only=True))


# --------------------------------------------------------------------------- #
# Web UI
# --------------------------------------------------------------------------- #
@pytest.fixture()
def web_app(tmp_path):
    workspace = Workspace(data_path=str(ATTACK_FIXTURE), sigmahq_path=str(SIGMAHQ_FIXTURE), offline=True)
    return WebApp(workspace, output_root=tmp_path / "out")


class TestWebApp:
    def test_status(self, web_app):
        status = web_app.status({})
        assert status["attack"]["version"] == "19.2"
        assert status["sigmahq"]["available"] and status["offline"]

    def test_search(self, web_app):
        assert web_app.search({"q": ["lsass"]})["results"][0]["id"] == "T1003.001"
        assert web_app.search({"q": ["cozy"], "kind": ["group"]})["results"][0]["id"] == "G0016"
        with pytest.raises(ApiError):
            web_app.search({"q": ["x"], "kind": ["weapon"]})

    def test_technique_includes_coverage(self, web_app):
        payload = web_app.technique("T1003.001")
        assert payload["sigmahq"]["status"] == "partial"
        assert payload["detection_strategies"][0]["analytics"][0]["log_sources"][0]["mappable"]

    def test_generate_payload(self, web_app):
        payload = web_app.generate({"technique": "T1003.001", "chains": True, "deterministic": True})
        assert payload["technique"]["id"] == "T1003.001"
        assert payload["rules"][0]["yaml"].startswith("#")
        chain = payload["chains"][0]
        assert chain["kind"] == "chain" and chain["timespan"] == "5m" and chain["steps"]
        assert payload["bundle"]["objects"]["indicator"] == 2
        assert payload["saved"] == []

    def test_generate_can_save(self, web_app, tmp_path):
        payload = web_app.generate({"technique": "T1059.001", "save": True})
        assert payload["saved"] and all((tmp_path / "out") in __import__("pathlib").Path(p).parents
                                        for p in payload["saved"])

    def test_pack_and_zip(self, web_app):
        pack = web_app.pack({"query": "S0002", "kind": "software", "chains": True})
        assert pack["summary"]["rules"] > 0
        assert any(path.startswith("sigma/") for path in pack["rule_files"])
        data, filename = web_app.pack_zip({"query": "S0002", "kind": "software"})
        assert filename == "s0002_mimikatz.zip"
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        assert "s0002_mimikatz/README.md" in names

    def test_update_is_refused_offline(self, web_app):
        with pytest.raises(ApiError) as error:
            web_app.update_sigmahq({})
        assert error.value.status == 409

    @pytest.mark.parametrize("body,message", [
        ({"level": "severe"}, "level"),
        ({"chains": "yes"}, "chains"),
        ({"tlp": "purple"}, "tlp"),
        ({"platform": "x" * 200}, "platform"),
        ({"author": 42}, "author"),
    ])
    def test_option_validation(self, body, message):
        with pytest.raises(ApiError, match=message):
            _options_from(body)


class TestWebServerSecurity:
    @pytest.fixture()
    def base_url(self, tmp_path):
        workspace = Workspace(data_path=str(ATTACK_FIXTURE), sigmahq_path=str(SIGMAHQ_FIXTURE), offline=True)
        server = create_server(workspace, "127.0.0.1", 0, output_root=tmp_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield f"http://127.0.0.1:{server.server_address[1]}"
        server.shutdown()
        server.server_close()

    @staticmethod
    def request(url, body=None, headers=None, method=None):
        data = json.dumps(body).encode() if body is not None else None
        default = {"Content-Type": "application/json", "X-Requested-With": "sigma-generator"} if body is not None else {}
        request = urllib.request.Request(url, data=data, headers={**default, **(headers or {})}, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    def test_page_and_security_headers(self, base_url):
        status, headers, body = self.request(base_url + "/")
        assert status == 200 and b"Sigma Generator" in body
        assert "default-src 'self'" in headers["Content-Security-Policy"]
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"

    def test_static_files_only(self, base_url):
        assert self.request(base_url + "/static/app.js")[0] == 200
        assert self.request(base_url + "/static/../server.py")[0] == 404
        assert self.request(base_url + "/static/server.py")[0] == 404

    def test_generate_happy_path(self, base_url):
        status, _, body = self.request(base_url + "/api/generate", {"technique": "T1059.001"})
        assert status == 200 and json.loads(body)["rules"]

    def test_csrf_header_required(self, base_url):
        status, _, _ = self.request(base_url + "/api/generate", {"technique": "T1059.001"},
                                    headers={"X-Requested-With": ""})
        assert status == 403

    def test_json_content_type_required(self, base_url):
        status, _, _ = self.request(base_url + "/api/generate", {"technique": "T1059.001"},
                                    headers={"Content-Type": "text/plain"})
        assert status == 415

    def test_dns_rebinding_host_rejected(self, base_url):
        assert self.request(base_url + "/api/status", headers={"Host": "attacker.example"})[0] == 403

    def test_body_size_limit(self, base_url):
        status, _, _ = self.request(base_url + "/api/generate", {"technique": "T1059.001", "author": "a" * 70000})
        assert status == 413

    def test_rejections_arrive_as_responses_not_resets(self, base_url):
        # Rejecting a request without reading its body used to reset the connection
        # on Windows, so clients saw "connection aborted" instead of the error.
        near_limit = {"technique": "T1059.001", "author": "a" * 60000}
        for _ in range(10):
            assert self.request(base_url + "/api/generate", near_limit, headers={"Content-Type": "text/plain"})[0] == 415
            assert self.request(base_url + "/api/generate", near_limit, headers={"X-Requested-With": ""})[0] == 403
            assert self.request(base_url + "/api/nope", near_limit)[0] == 404
            assert self.request(base_url + "/api/generate", {"author": "a" * 200000})[0] == 413

    def test_invalid_input_and_methods(self, base_url):
        assert self.request(base_url + "/api/generate", {"technique": "T1059.001", "level": "x"})[0] == 400
        assert self.request(base_url + "/api/generate", method="PUT")[0] == 405
        assert self.request(base_url + "/api/nope")[0] == 404
        status, _, body = self.request(base_url + "/api/threat/NoSuchGroup")
        assert status == 422 and b"Traceback" not in body


# --------------------------------------------------------------------------- #
# CLI for the new commands
# --------------------------------------------------------------------------- #
class TestNewCommands:
    COMMON = ["--data", str(ATTACK_FIXTURE), "--sigmahq", str(SIGMAHQ_FIXTURE), "--offline"]

    def test_gaps_for_a_technique(self, capsys):
        assert main(["gaps", "T1003.001", *self.COMMON]) == 0
        out = capsys.readouterr().out
        assert "SigmaHQ r2026-07-01" in out and "GAP" in out and "--gaps-only" in out

    def test_gaps_json(self, capsys):
        assert main(["gaps", "T1003.001", "--json", *self.COMMON]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["techniques"][0]["status"] == "partial"

    def test_gaps_for_a_group(self, capsys):
        assert main(["gaps", "--group", "APT29", *self.COMMON]) == 0
        out = capsys.readouterr().out
        assert "APT29 (G0016)" in out and "have no SigmaHQ rule" in out

    def test_generate_with_chains(self, tmp_path, capsys):
        assert main(["generate", "T1003.001", "--chains", "--deterministic", "-o", str(tmp_path), *self.COMMON]) == 0
        assert list((tmp_path / "sigma").glob("mr_*.yml"))
        assert "1 correlation rule(s)" in capsys.readouterr().out

    def test_generate_gaps_only(self, tmp_path, capsys):
        assert main(["generate", "T1003.001", "--gaps-only", "-o", str(tmp_path), *self.COMMON]) == 0
        rule = next((tmp_path / "sigma").glob("*.yml")).read_text(encoding="utf-8")
        assert "process_access" not in rule.split("logsource:")[1].split("detection:")[0]

    def test_generate_pack(self, tmp_path, capsys):
        assert main(["generate", "--group", "Cozy Bear", "--chains", "--deterministic",
                     "-o", str(tmp_path), *self.COMMON]) == 0
        folder = tmp_path / "packs" / "g0016_apt29"
        assert (folder / "README.md").is_file() and (folder / "g0016_apt29_bundle.json").is_file()
        assert "Detection pack for APT29 (G0016)" in capsys.readouterr().out
        assert main(["validate", str(folder)]) == 0

    def test_pack_argument_conflicts(self, tmp_path):
        assert main(["generate", "T1059.001", "--group", "APT29", *self.COMMON]) == 1
        assert main(["generate", "--group", "APT29", "--stdout", *self.COMMON]) == 1

    def test_search_and_info_for_threats(self, capsys):
        assert main(["search", "cozy", "--groups", *self.COMMON]) == 0
        assert "G0016" in capsys.readouterr().out
        assert main(["info", "S0002", *self.COMMON]) == 0
        assert "Mimikatz" in capsys.readouterr().out
        assert main(["info", "G0016", "--json", *self.COMMON]) == 0
        assert json.loads(capsys.readouterr().out)["kind"] == "group"

    def test_validate_reports_broken_correlation(self, tmp_path, capsys):
        path = tmp_path / "mr_broken.yml"
        path.write_text("title: broken\ncorrelation:\n    type: temporal\n    rules: [ghost]\n", encoding="utf-8")
        assert main(["validate", str(path)]) == 3
        assert "FAIL" in capsys.readouterr().out
