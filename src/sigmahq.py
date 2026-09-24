"""SigmaHQ rule index and ATT&CK detection-gap analysis.

SigmaHQ (https://github.com/SigmaHQ/sigma) publishes thousands of community
rules tagged with ATT&CK technique IDs.  For a given technique this module
answers the question a detection engineer actually has:

    ATT&CK says to watch *these* log sources - which of them does the
    community already have a rule for, and which are gaps?

The release zip is parsed once into a compact JSON index under ``data/`` so
coverage checks are instant afterwards.
"""

from __future__ import annotations

import io
import json
import os
import re
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from .attack_fetcher import Analytic, LogSourceRef, Technique
from .mappings import TelemetryMapping, resolve_telemetry
from .utils import (
    LOG,
    DataUnavailableError,
    ensure_dir,
    env_int,
    env_str,
    format_bytes,
    resolve_path,
    utcnow_iso,
)

DEFAULT_RELEASE_URL = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip"
INDEX_FILENAME = "sigmahq-index.json"
INDEX_FORMAT = 1
RULE_URL = "https://github.com/SigmaHQ/sigma/blob/master/{path}"

_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_RELEASE_TAG_RE = re.compile(r"/releases/download/([^/]+)/")


# --------------------------------------------------------------------------- #
# Index
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SigmaHQRule:
    """The parts of a SigmaHQ rule that coverage analysis needs."""

    id: str
    title: str
    path: str
    status: str = ""
    level: str = ""
    category: Optional[str] = None
    product: Optional[str] = None
    service: Optional[str] = None
    techniques: tuple[str, ...] = ()
    event_ids: tuple[int, ...] = ()

    @property
    def url(self) -> str:
        return RULE_URL.format(path=self.path)

    @property
    def logsource_label(self) -> str:
        return "/".join(v for v in (self.category, self.product, self.service) if v) or "unknown"


def _event_ids(detection: Any) -> tuple[int, ...]:
    """Collect every ``EventID`` value used anywhere in a detection block."""
    found: set[int] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key).split("|", 1)[0] == "EventID":
                    for item in value if isinstance(value, list) else [value]:
                        try:
                            found.add(int(item))
                        except (TypeError, ValueError):
                            continue
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(detection)
    return tuple(sorted(found))


def parse_rule_document(document: Any, path: str) -> Optional[SigmaHQRule]:
    """Turn one parsed SigmaHQ YAML document into an index entry (or None)."""
    if not isinstance(document, dict) or "correlation" in document:
        return None
    if document.get("status") == "deprecated" or "/deprecated/" in path:
        return None
    techniques = []
    for tag in document.get("tags") or []:
        match = _TECHNIQUE_TAG_RE.match(str(tag))
        if match:
            techniques.append(match.group(1).upper())
    if not techniques:
        return None
    logsource = document.get("logsource") or {}
    if not isinstance(logsource, dict):
        return None
    return SigmaHQRule(
        id=str(document.get("id", "")),
        title=str(document.get("title", "")),
        path=path,
        status=str(document.get("status", "")),
        level=str(document.get("level", "")),
        category=(str(logsource["category"]).lower() if logsource.get("category") else None),
        product=(str(logsource["product"]).lower() if logsource.get("product") else None),
        service=(str(logsource["service"]).lower() if logsource.get("service") else None),
        techniques=tuple(dict.fromkeys(techniques)),
        event_ids=_event_ids(document.get("detection")),
    )


class SigmaHQIndex:
    """Technique -> SigmaHQ rules lookup."""

    def __init__(self, rules: Iterable[SigmaHQRule], release: str = "unknown",
                 source: str = "<memory>", built_at: str = "", total_rules: int = 0) -> None:
        self.rules: list[SigmaHQRule] = list(rules)
        self.release = release
        self.source = source
        self.built_at = built_at
        self.total_rules = total_rules or len(self.rules)
        self._by_technique: dict[str, list[SigmaHQRule]] = {}
        for rule in self.rules:
            for technique_id in rule.techniques:
                self._by_technique.setdefault(technique_id, []).append(rule)

    # -- construction ------------------------------------------------------ #
    @classmethod
    def build_from_zip(cls, data: bytes, release: str = "unknown") -> "SigmaHQIndex":
        rules: list[SigmaHQRule] = []
        total = 0
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in archive.namelist():
                if not name.endswith((".yml", ".yaml")):
                    continue
                try:
                    documents = list(yaml.safe_load_all(archive.read(name)))
                except yaml.YAMLError as exc:
                    LOG.debug("Skipping unparseable SigmaHQ file %s: %s", name, exc)
                    continue
                for document in documents:
                    total += 1
                    rule = parse_rule_document(document, name)
                    if rule:
                        rules.append(rule)
        if not total:
            raise DataUnavailableError("The SigmaHQ archive contained no rules")
        return cls(rules, release=release, built_at=utcnow_iso(), total_rules=total)

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "SigmaHQIndex":
        index_path = Path(path)
        if not index_path.is_file():
            raise DataUnavailableError(f"SigmaHQ index not found: {index_path}")
        try:
            payload = json.loads(index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise DataUnavailableError(f"{index_path} is not valid JSON ({exc})") from exc
        if payload.get("format") != INDEX_FORMAT:
            raise DataUnavailableError(
                f"{index_path} was built by a different version of this tool - run `update --sigmahq-only`"
            )
        rules = [
            SigmaHQRule(**{**entry, "techniques": tuple(entry["techniques"]),
                           "event_ids": tuple(entry.get("event_ids", ()))})
            for entry in payload.get("rules", [])
        ]
        return cls(rules, release=payload.get("release", "unknown"), source=str(index_path),
                   built_at=payload.get("built_at", ""), total_rules=payload.get("total_rules", 0))

    @classmethod
    def load(cls, path: Optional[str | os.PathLike[str]] = None, offline: bool = False,
             timeout: Optional[int] = None) -> "SigmaHQIndex":
        index_path = default_index_path(path)
        if index_path.is_file():
            return cls.from_file(index_path)
        if offline:
            raise DataUnavailableError(
                f"No SigmaHQ index at {index_path} and offline mode is on.\n"
                "Fetch it once with:  python -m src.main update --sigmahq-only"
            )
        return download_index(index_path, timeout=timeout)

    def save(self, path: str | os.PathLike[str]) -> Path:
        target = Path(path)
        ensure_dir(target.parent)
        payload = {
            "format": INDEX_FORMAT,
            "release": self.release,
            "built_at": self.built_at,
            "total_rules": self.total_rules,
            "rules": [asdict(rule) for rule in self.rules],
        }
        target.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        self.source = str(target)
        return target

    # -- queries ----------------------------------------------------------- #
    def rules_for(self, technique_id: str) -> list[SigmaHQRule]:
        """Rules tagged with exactly this technique."""
        return list(self._by_technique.get(technique_id.upper(), []))

    def related_rules(self, technique_id: str) -> list[SigmaHQRule]:
        """Rules tagged with the parent or a sub-technique, but not the technique itself."""
        key = technique_id.upper()
        parent = key.split(".", 1)[0]
        exact_ids = {rule.id for rule in self.rules_for(key)}
        related: dict[str, SigmaHQRule] = {}
        for tagged, rules in self._by_technique.items():
            if tagged == key:
                continue
            # A sub-technique's parent is related; so are a parent's sub-techniques.
            # Siblings (T1003.001 vs T1003.002) are different behaviours and are not.
            if (tagged == parent and "." in key) or tagged.startswith(key + "."):
                for rule in rules:
                    if rule.id not in exact_ids:
                        related[rule.id] = rule
        return sorted(related.values(), key=lambda rule: rule.title)

    @property
    def technique_count(self) -> int:
        return len(self._by_technique)


def default_index_path(path: Optional[str | os.PathLike[str]] = None) -> Path:
    return resolve_path(path, env_str("SIGMAHQ_INDEX_PATH", f"data/{INDEX_FILENAME}"))


def download_index(destination: Optional[str | os.PathLike[str]] = None, url: Optional[str] = None,
                   timeout: Optional[int] = None) -> SigmaHQIndex:
    """Download the newest SigmaHQ release and build the local index."""
    try:
        import requests
    except ImportError as exc:  # pragma: no cover - environment specific
        raise DataUnavailableError("The 'requests' package is required to download SigmaHQ rules") from exc

    release_url = url or env_str("SIGMAHQ_RELEASE_URL", DEFAULT_RELEASE_URL)
    LOG.info("Downloading SigmaHQ rules from %s", release_url)
    try:
        response = requests.get(release_url, timeout=timeout or env_int("ATTACK_HTTP_TIMEOUT", 60))
        response.raise_for_status()
    except Exception as exc:
        raise DataUnavailableError(f"Could not download SigmaHQ rules: {exc}") from exc

    # "releases/latest/download" redirects via /releases/download/<tag>/ to a
    # storage host, so the tag lives in the redirect chain, not the final URL.
    hops = [release_url, response.url or ""]
    for hop in response.history:
        hops += [hop.url or "", hop.headers.get("Location", "")]
    release = next((m.group(1) for m in map(_RELEASE_TAG_RE.search, hops) if m), "unknown")
    LOG.info("Downloaded SigmaHQ %s (%s); indexing...", release, format_bytes(len(response.content)))
    try:
        index = SigmaHQIndex.build_from_zip(response.content, release=release)
    except zipfile.BadZipFile as exc:
        raise DataUnavailableError(f"{release_url} did not return a zip archive") from exc

    index.save(default_index_path(destination))
    LOG.info("Indexed %d ATT&CK-tagged rules (of %d) covering %d techniques",
             len(index.rules), index.total_rules, index.technique_count)
    return index


# --------------------------------------------------------------------------- #
# Coverage analysis
# --------------------------------------------------------------------------- #
#: Sigma categories that subsume more specific ones for coverage purposes.
_UMBRELLA_CATEGORIES = {
    "registry_event": ("registry_add", "registry_set", "registry_delete", "registry_rename"),
}


def rule_covers(rule: SigmaHQRule, mapping: TelemetryMapping) -> bool:
    """Does an existing SigmaHQ rule watch the telemetry ``mapping`` resolves to?"""
    logsource = mapping.logsource
    category = (logsource.category or "").lower() or None
    product = (logsource.product or "").lower() or None
    service = (logsource.service or "").lower() or None

    if category:
        same_category = rule.category == category or category in _UMBRELLA_CATEGORIES.get(rule.category or "", ())
        return same_category and (rule.product is None or product is None or rule.product == product)

    if not (product and rule.product == product and rule.category is None):
        return False
    if service and rule.service != service:
        return False
    wanted = mapping.base_selection.get("EventID")
    if wanted is not None and rule.event_ids:
        wanted_ids = set(wanted if isinstance(wanted, list) else [wanted])
        return bool(wanted_ids & set(rule.event_ids))
    return True


@dataclass
class SourceCoverage:
    """One ATT&CK analytic log source and the SigmaHQ rules that watch it."""

    analytic_id: str
    platform: Optional[str]
    log_source: LogSourceRef
    mapping: TelemetryMapping
    rules: list[SigmaHQRule] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.mapping.is_usable

    @property
    def covered(self) -> bool:
        return bool(self.rules)


@dataclass
class CoverageReport:
    """SigmaHQ coverage of the telemetry ATT&CK recommends for one technique."""

    technique_id: str
    technique_name: str
    sigmahq_release: str
    exact_rules: list[SigmaHQRule] = field(default_factory=list)
    related_rules: list[SigmaHQRule] = field(default_factory=list)
    sources: list[SourceCoverage] = field(default_factory=list)

    @property
    def usable_sources(self) -> list[SourceCoverage]:
        return [source for source in self.sources if source.usable]

    @property
    def gaps(self) -> list[SourceCoverage]:
        return [source for source in self.usable_sources if not source.covered]

    @property
    def covered_sources(self) -> list[SourceCoverage]:
        return [source for source in self.usable_sources if source.covered]

    @property
    def status(self) -> str:
        if not self.usable_sources:
            return "unmappable"
        if not self.exact_rules:
            return "no-rules"
        if not self.gaps:
            return "covered"
        return "partial" if self.covered_sources else "gap"

    @property
    def coverage_ratio(self) -> float:
        usable = self.usable_sources
        return len(self.covered_sources) / len(usable) if usable else 0.0

    def is_covered(self, mapping: TelemetryMapping) -> bool:
        """True when SigmaHQ already has a rule for this technique on this telemetry."""
        return any(rule_covers(rule, mapping) for rule in self.exact_rules)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": {"id": self.technique_id, "name": self.technique_name},
            "sigmahq_release": self.sigmahq_release,
            "status": self.status,
            "coverage_ratio": round(self.coverage_ratio, 3),
            "sigmahq_rules": [
                {"id": r.id, "title": r.title, "logsource": r.logsource_label, "status": r.status,
                 "level": r.level, "url": r.url}
                for r in self.exact_rules
            ],
            "related_rules": len(self.related_rules),
            "sources": [
                {
                    "analytic": s.analytic_id,
                    "platform": s.platform,
                    "attack_log_source": s.log_source.describe(),
                    "sigma_logsource": s.mapping.logsource.as_dict(),
                    "usable": s.usable,
                    "covered_by": [r.id for r in s.rules],
                }
                for s in self.sources
            ],
            "gaps": [
                {"analytic": s.analytic_id, "attack_log_source": s.log_source.describe(),
                 "sigma_logsource": s.mapping.logsource.as_dict()}
                for s in self.gaps
            ],
        }


def assess_coverage(technique: Technique, index: SigmaHQIndex) -> CoverageReport:
    """Compare ATT&CK's recommended telemetry for ``technique`` with SigmaHQ."""
    report = CoverageReport(
        technique_id=technique.id,
        technique_name=technique.name,
        sigmahq_release=index.release,
        exact_rules=index.rules_for(technique.id),
        related_rules=index.related_rules(technique.id),
    )
    seen: set[tuple[str, str, str]] = set()
    for analytic in technique.analytics:
        platform = analytic.platforms[0] if analytic.platforms else None
        for log_source in analytic.log_sources:
            key = (analytic.id, log_source.name, log_source.channel or "")
            if key in seen:
                continue
            seen.add(key)
            mapping = resolve_telemetry(log_source.name, log_source.channel, log_source.data_component, platform)
            covering = [rule for rule in report.exact_rules if mapping.is_usable and rule_covers(rule, mapping)]
            report.sources.append(SourceCoverage(analytic.id, platform, log_source, mapping, covering))
    return report
