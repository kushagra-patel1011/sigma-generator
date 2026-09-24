"""Browser build: the ATT&CK bundle may only lose data the generator never
reads, and the hosted page must stay a transformation of the served one."""

from __future__ import annotations

import json

import pytest

from conftest import ATTACK_FIXTURE
from src.attack_fetcher import AttackDataset
from tools import corpus, webapp


@pytest.fixture(scope="module")
def fixture_payload():
    return json.loads(ATTACK_FIXTURE.read_text(encoding="utf-8"))


class TestTrimmedBundle:
    def test_output_is_identical_to_the_full_bundle(self, fixture_payload):
        full = corpus.build_digest(AttackDataset(fixture_payload))
        slim = corpus.build_digest(AttackDataset(webapp.trim_bundle(fixture_payload)))
        assert corpus.dump_digest(slim) == corpus.dump_digest(full)

    def test_it_really_trims(self, fixture_payload):
        slim = webapp.trim_bundle(fixture_payload)
        assert len(slim["objects"]) < len(fixture_payload["objects"])
        assert len(json.dumps(slim)) < len(json.dumps(fixture_payload)) * 0.9

    def test_threat_profiles_survive(self, fixture_payload):
        """Packs need groups, software, campaigns and their procedure prose."""
        dataset = AttackDataset(webapp.trim_bundle(fixture_payload))
        group = dataset.get_threat("G0016")
        assert group.technique_ids and any(p.description for p in group.procedures)
        assert dataset.get_threat("S0002").platforms == ("Windows",)

    def test_data_component_names_survive(self, fixture_payload):
        """Analytic log sources name a data component through a reference; drop
        those objects and telemetry silently resolves differently."""
        dataset = AttackDataset(webapp.trim_bundle(fixture_payload))
        analytics = dataset.get_technique("T1003.001").analytics
        assert any(ref.data_component for analytic in analytics for ref in analytic.log_sources)


class TestPage:
    def test_it_rewires_the_served_page(self):
        page = webapp.build_page("sigma_generator-9.9.9-py3-none-any.whl")
        assert 'data-wheel="sigma_generator-9.9.9-py3-none-any.whl"' in page
        assert '<script src="runtime.js"></script>' in page
        assert "/static/app.js" not in page and "/static/styles.css" not in page
        assert 'id="boot"' in page and 'id="boot-bar"' in page

    def test_it_fails_loudly_if_the_page_changes(self, monkeypatch, tmp_path):
        rewritten = tmp_path / "index.html"
        rewritten.write_text("<html><body>no markers here</body></html>", encoding="utf-8")
        monkeypatch.setattr(webapp, "STATIC_DIR", tmp_path)
        with pytest.raises(SystemExit, match="update tools/webapp.py"):
            webapp.build_page("x.whl")
