"""Load MITRE ATT&CK STIX data and expose it as plain Python objects.

The upstream bundle is a ~55 MB STIX 2.1 file published by MITRE at
https://github.com/mitre-attack/attack-stix-data.  This module caches it under
``data/``, indexes it once, and answers the questions the generator asks:

* give me technique ``T1059.001``
* what detection strategies / analytics does ATT&CK attach to it
* what log sources do those analytics name

ATT&CK v18 moved detection guidance out of the technique object (the old
``x_mitre_detection`` prose and ``x_mitre_data_sources`` strings) and into
``x-mitre-detection-strategy`` / ``x-mitre-analytic`` objects.  Both shapes are
supported so the tool keeps working against older pinned bundles.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from .utils import (
    LOG,
    DataUnavailableError,
    TechniqueNotFoundError,
    ThreatNotFoundError,
    clean_text,
    ensure_dir,
    env_int,
    env_str,
    format_bytes,
    sha256_file,
    utcnow_iso,
)

DEFAULT_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
DEFAULT_COLLECTION = "Enterprise ATT&CK"
META_FILENAME = ".attack-meta.json"

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
THREAT_ID_RE = re.compile(r"^[GSC]\d{4}$", re.IGNORECASE)

#: STIX types ATT&CK uses for the things that *use* techniques, by user-facing kind.
THREAT_KINDS: dict[str, tuple[str, ...]] = {
    "group": ("intrusion-set",),
    "software": ("malware", "tool"),
    "campaign": ("campaign",),
}
_KIND_BY_PREFIX = {"G": "group", "S": "software", "C": "campaign"}
_KIND_BY_STIX_TYPE = {stix_type: kind for kind, types in THREAT_KINDS.items() for stix_type in types}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class LogSourceRef:
    """One ``x_mitre_log_source_references`` entry of an analytic."""

    name: str
    channel: Optional[str] = None
    data_component: Optional[str] = None
    data_source: Optional[str] = None

    def describe(self) -> str:
        return f"{self.name} ({self.channel})" if self.channel else self.name


@dataclass(frozen=True)
class Analytic:
    """An ATT&CK analytic (``AN####``) - the detection idea plus its telemetry."""

    id: str
    stix_id: str
    name: str
    description: str
    platforms: tuple[str, ...] = ()
    log_sources: tuple[LogSourceRef, ...] = ()
    mutable_elements: tuple[tuple[str, str], ...] = ()
    url: str = ""


@dataclass(frozen=True)
class DetectionStrategy:
    """An ATT&CK detection strategy (``DET####``) grouping related analytics."""

    id: str
    stix_id: str
    name: str
    analytics: tuple[Analytic, ...] = ()
    url: str = ""


@dataclass
class Technique:
    """Everything the generator needs to know about one ATT&CK technique."""

    id: str
    stix_id: str
    name: str
    description: str = ""
    url: str = ""
    platforms: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()          # kill-chain shortnames, e.g. "execution"
    is_subtechnique: bool = False
    parent_id: Optional[str] = None
    parent_name: Optional[str] = None
    version: str = ""
    created: str = ""
    modified: str = ""
    deprecated: bool = False
    revoked: bool = False
    revoked_by: Optional[str] = None
    detection_strategies: tuple[DetectionStrategy, ...] = ()
    legacy_detection: str = ""              # pre-v18 x_mitre_detection prose
    legacy_data_sources: tuple[str, ...] = ()
    references: tuple[tuple[str, str], ...] = ()   # (source_name, url)
    kill_chain_phases: tuple[dict[str, str], ...] = ()
    mitigations: tuple[str, ...] = ()
    detects_ref_count: int = 0

    @property
    def analytics(self) -> tuple[Analytic, ...]:
        return tuple(a for strategy in self.detection_strategies for a in strategy.analytics)

    @property
    def has_detection_model(self) -> bool:
        return bool(self.detection_strategies) or bool(self.legacy_data_sources)

    def strategy_for(self, analytic: Analytic) -> Optional[DetectionStrategy]:
        for strategy in self.detection_strategies:
            if analytic in strategy.analytics:
                return strategy
        return None

    def summary_line(self) -> str:
        scope = "sub-technique" if self.is_subtechnique else "technique"
        return f"{self.id} - {self.name} ({scope}, {', '.join(self.tactics) or 'no tactic'})"


@dataclass(frozen=True)
class Procedure:
    """How one group/software/campaign used one technique, per ATT&CK."""

    technique_id: str
    technique_name: str
    description: str
    relationship_id: str = ""
    via: str = ""            # campaign ID when inherited through --with-campaigns


@dataclass
class ThreatProfile:
    """An ATT&CK group (G####), software (S####) or campaign (C####)."""

    id: str
    stix_id: str
    stix_type: str
    kind: str
    name: str
    aliases: tuple[str, ...] = ()
    description: str = ""
    url: str = ""
    created: str = ""
    modified: str = ""
    procedures: tuple[Procedure, ...] = ()
    campaigns: tuple[str, ...] = ()       # campaign IDs attributed to a group
    platforms: tuple[str, ...] = ()

    @property
    def technique_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(procedure.technique_id for procedure in self.procedures))

    def procedures_for(self, technique_id: str) -> tuple[Procedure, ...]:
        return tuple(p for p in self.procedures if p.technique_id == technique_id)

    @property
    def label(self) -> str:
        return f"{self.name} ({self.id})"

    @property
    def sigma_tag(self) -> Optional[str]:
        """Sigma's attack namespace has tags for groups and software, not campaigns."""
        return f"attack.{self.id.lower()}" if self.kind in ("group", "software") else None


# --------------------------------------------------------------------------- #
# Download helpers
# --------------------------------------------------------------------------- #
def _requests():
    try:
        import requests  # imported lazily so offline use needs no dependency
    except ImportError as exc:  # pragma: no cover - environment specific
        raise DataUnavailableError(
            "The 'requests' package is required to download ATT&CK data. "
            "Install it with `pip install -r requirements.txt`, or run with --offline "
            "and supply the bundle yourself."
        ) from exc
    return requests


def resolve_latest_url(index_url: str = DEFAULT_INDEX_URL, collection: str = DEFAULT_COLLECTION,
                       timeout: int = 60) -> tuple[str, str]:
    """Return ``(bundle_url, version)`` for the newest release of ``collection``."""
    requests = _requests()
    LOG.info("Resolving newest %s release from %s", collection, index_url)
    try:
        response = requests.get(index_url, timeout=timeout)
        response.raise_for_status()
        index = response.json()
    except Exception as exc:
        raise DataUnavailableError(f"Could not read the ATT&CK collection index: {exc}") from exc

    for entry in index.get("collections", []):
        if entry.get("name") != collection:
            continue
        versions = entry.get("versions") or []
        if not versions:
            break
        newest = max(versions, key=lambda v: _version_key(v.get("version", "0")))
        return newest["url"], newest.get("version", "unknown")
    raise DataUnavailableError(f"Collection '{collection}' is not listed in {index_url}")


def _version_key(version: str) -> tuple[int, ...]:
    parts = []
    for chunk in str(version).split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def download_bundle(destination: str | os.PathLike[str], url: Optional[str] = None,
                    index_url: Optional[str] = None, timeout: int = 60,
                    collection: str = DEFAULT_COLLECTION) -> Path:
    """Download the ATT&CK bundle to ``destination`` and write a metadata sidecar."""
    requests = _requests()
    target = Path(destination)
    ensure_dir(target.parent)

    version = "unknown"
    if not url:
        url, version = resolve_latest_url(index_url or DEFAULT_INDEX_URL, collection, timeout)

    LOG.info("Downloading %s", url)
    tmp_handle, tmp_name = tempfile.mkstemp(dir=str(target.parent), suffix=".part")
    os.close(tmp_handle)
    tmp_path = Path(tmp_name)
    try:
        with requests.get(url, timeout=timeout, stream=True) as response:
            response.raise_for_status()
            # With Content-Encoding (GitHub gzips raw files) the header counts
            # compressed bytes while iter_content yields decompressed ones.
            compressed = bool(response.headers.get("Content-Encoding"))
            total = 0 if compressed else int(response.headers.get("Content-Length") or 0)
            written = 0
            with open(tmp_path, "wb") as handle:
                for chunk in response.iter_content(chunk_size=1 << 20):
                    if not chunk:
                        continue
                    handle.write(chunk)
                    written += len(chunk)
            LOG.info("Downloaded %s%s", format_bytes(written),
                     f" of {format_bytes(total)}" if total else "")
        # Fail before clobbering a good cache if the payload is not ATT&CK STIX.
        with open(tmp_path, encoding="utf-8") as handle:
            payload = json.load(handle)
        if payload.get("type") != "bundle" or not payload.get("objects"):
            raise DataUnavailableError(f"{url} did not return a STIX bundle")

        shutil.move(str(tmp_path), str(target))
    except DataUnavailableError:
        tmp_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        tmp_path.unlink(missing_ok=True)
        raise DataUnavailableError(f"Download of {url} failed: {exc}") from exc

    meta = {
        "url": url,
        "version": _collection_version(payload) or version,
        "downloaded_at": utcnow_iso(),
        "object_count": len(payload.get("objects", [])),
        "sha256": sha256_file(target),
        "size_bytes": target.stat().st_size,
    }
    (target.parent / META_FILENAME).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    LOG.info("Cached ATT&CK %s (%d objects) at %s", meta["version"], meta["object_count"], target)
    return target


def _collection_version(payload: dict[str, Any]) -> Optional[str]:
    for obj in payload.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return str(obj.get("x_mitre_version") or "") or None
    return None


# --------------------------------------------------------------------------- #
# Dataset
# --------------------------------------------------------------------------- #
class AttackDataset:
    """An indexed, queryable ATT&CK bundle."""

    def __init__(self, payload: dict[str, Any], source: str = "<memory>") -> None:
        objects = payload.get("objects")
        if not isinstance(objects, list) or not objects:
            raise DataUnavailableError(f"{source} does not look like a STIX bundle (no objects)")
        self.source = source
        self._objects: list[dict[str, Any]] = objects
        self._by_stix_id: dict[str, dict[str, Any]] = {}
        self._by_attack_id: dict[str, dict[str, Any]] = {}
        self._detects: dict[str, list[str]] = {}       # attack-pattern stix id -> strategy stix ids
        self._subtechnique_parent: dict[str, str] = {}
        self._mitigates: dict[str, list[str]] = {}
        self._revoked_by: dict[str, str] = {}
        self._uses: dict[str, list[dict[str, Any]]] = {}        # user stix id -> uses relationships
        self._attributed: dict[str, list[str]] = {}             # group stix id -> campaign stix ids
        self.version = _collection_version(payload) or "unknown"
        self._index()

    # -- construction ------------------------------------------------------ #
    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "AttackDataset":
        file_path = Path(path)
        if not file_path.is_file():
            raise DataUnavailableError(f"ATT&CK bundle not found: {file_path}")
        LOG.debug("Loading ATT&CK bundle from %s", file_path)
        try:
            with open(file_path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except json.JSONDecodeError as exc:
            raise DataUnavailableError(
                f"{file_path} is not valid JSON ({exc}). Delete it and re-run with `update`."
            ) from exc
        return cls(payload, source=str(file_path))

    @classmethod
    def load(
        cls,
        path: Optional[str | os.PathLike[str]] = None,
        url: Optional[str] = None,
        offline: bool = False,
        auto_download: bool = True,
        timeout: Optional[int] = None,
    ) -> "AttackDataset":
        """Load from cache, downloading it first when the cache is cold."""
        data_path = Path(path or env_str("ATTACK_DATA_PATH", "data/enterprise-attack.json"))
        if not data_path.is_absolute():
            from .utils import PROJECT_ROOT

            data_path = PROJECT_ROOT / data_path

        if data_path.is_file():
            return cls.from_file(data_path)

        if offline or not auto_download:
            raise DataUnavailableError(
                f"No ATT&CK bundle at {data_path} and offline mode is on.\n"
                "Fetch it once with:  python -m src.main update"
            )
        download_bundle(
            data_path,
            url=url or os.environ.get("ATTACK_DATA_URL"),
            index_url=env_str("ATTACK_INDEX_URL", DEFAULT_INDEX_URL),
            timeout=timeout if timeout is not None else env_int("ATTACK_HTTP_TIMEOUT", 60),
        )
        return cls.from_file(data_path)

    # -- indexing ---------------------------------------------------------- #
    def _index(self) -> None:
        for obj in self._objects:
            stix_id = obj.get("id")
            if not stix_id:
                continue
            self._by_stix_id[stix_id] = obj

            attack_id = external_id(obj)
            if attack_id:
                # Keep the newest object when ATT&CK ships duplicates.
                existing = self._by_attack_id.get(attack_id)
                if existing is None or str(obj.get("modified", "")) >= str(existing.get("modified", "")):
                    self._by_attack_id[attack_id] = obj

        for obj in self._objects:
            if obj.get("type") != "relationship":
                continue
            rel_type = obj.get("relationship_type")
            source_ref, target_ref = obj.get("source_ref", ""), obj.get("target_ref", "")
            if rel_type == "detects" and target_ref.startswith("attack-pattern--"):
                self._detects.setdefault(target_ref, []).append(source_ref)
            elif rel_type == "subtechnique-of":
                self._subtechnique_parent[source_ref] = target_ref
            elif rel_type == "mitigates" and target_ref.startswith("attack-pattern--"):
                self._mitigates.setdefault(target_ref, []).append(source_ref)
            elif rel_type == "revoked-by":
                self._revoked_by[source_ref] = target_ref
            elif rel_type == "uses" and target_ref.startswith("attack-pattern--"):
                if not (obj.get("revoked") or obj.get("x_mitre_deprecated")):
                    self._uses.setdefault(source_ref, []).append(obj)
            elif rel_type == "attributed-to" and source_ref.startswith("campaign--"):
                self._attributed.setdefault(target_ref, []).append(source_ref)

        LOG.debug(
            "Indexed %d objects (%d techniques, %d detection strategies)",
            len(self._objects), len(self.technique_ids()), self.count("x-mitre-detection-strategy"),
        )

    # -- queries ----------------------------------------------------------- #
    def count(self, stix_type: str) -> int:
        return sum(1 for obj in self._objects if obj.get("type") == stix_type)

    def technique_ids(self) -> list[str]:
        return sorted(
            attack_id for attack_id, obj in self._by_attack_id.items()
            if obj.get("type") == "attack-pattern" and TECHNIQUE_ID_RE.match(attack_id)
        )

    def iter_techniques(self) -> Iterator[dict[str, Any]]:
        for obj in self._objects:
            if obj.get("type") == "attack-pattern" and "enterprise-attack" in (obj.get("x_mitre_domains") or ["enterprise-attack"]):
                yield obj

    def search(self, query: str, limit: int = 25, include_deprecated: bool = False) -> list[Technique]:
        """Case-insensitive search across technique IDs, names and descriptions."""
        needle = query.strip().lower()
        if not needle:
            return []
        scored: list[tuple[int, str]] = []
        for obj in self.iter_techniques():
            if not include_deprecated and (obj.get("revoked") or obj.get("x_mitre_deprecated")):
                continue
            attack_id = external_id(obj) or ""
            name = (obj.get("name") or "").lower()
            if needle == attack_id.lower():
                score = 0
            elif needle in name:
                score = 1 if name.startswith(needle) else 2
            elif attack_id.lower().startswith(needle):
                score = 3
            elif needle in (obj.get("description") or "").lower():
                score = 4
            else:
                continue
            scored.append((score, attack_id))
        scored.sort(key=lambda item: (item[0], item[1]))
        return [self.get_technique(attack_id) for _, attack_id in scored[:limit]]

    def get_technique(self, technique_id: str, follow_revoked: bool = False) -> Technique:
        """Look up a technique by ATT&CK ID (``T1059`` / ``T1059.001``)."""
        key = (technique_id or "").strip().upper()
        if not key:
            raise TechniqueNotFoundError("No technique ID given")
        if not TECHNIQUE_ID_RE.match(key):
            raise TechniqueNotFoundError(
                f"'{technique_id}' is not an ATT&CK technique ID (expected e.g. T1059 or T1059.001)"
            )
        obj = self._by_attack_id.get(key)
        if obj is None or obj.get("type") != "attack-pattern":
            raise TechniqueNotFoundError(
                f"{key} is not in this ATT&CK bundle ({self.source}). "
                "It may be newer than the cached data - try `python -m src.main update`."
            )

        technique = self._build_technique(obj)
        if technique.revoked and follow_revoked and technique.revoked_by:
            LOG.warning("%s is revoked; following it to %s", key, technique.revoked_by)
            return self.get_technique(technique.revoked_by)
        return technique

    # -- threat profiles (groups, software, campaigns) ---------------------- #
    def raw_object(self, stix_id: str) -> Optional[dict[str, Any]]:
        """The untouched STIX object, for re-publishing faithful subsets."""
        return self._by_stix_id.get(stix_id)

    def _threat_objects(self, kind: Optional[str] = None) -> Iterator[dict[str, Any]]:
        stix_types = THREAT_KINDS[kind] if kind else tuple(_KIND_BY_STIX_TYPE)
        for obj in self._objects:
            if obj.get("type") in stix_types and external_id(obj):
                yield obj

    @staticmethod
    def _aliases(obj: dict[str, Any]) -> tuple[str, ...]:
        names = list(obj.get("aliases") or []) + list(obj.get("x_mitre_aliases") or [])
        return tuple(dict.fromkeys(name for name in names if name))

    def search_threats(self, query: str, kind: Optional[str] = None, limit: int = 25,
                       include_deprecated: bool = False) -> list[ThreatProfile]:
        """Case-insensitive search over group/software/campaign IDs, names and aliases."""
        needle = query.strip().lower()
        if not needle:
            return []
        scored: list[tuple[int, str, dict[str, Any]]] = []
        for obj in self._threat_objects(kind):
            if not include_deprecated and (obj.get("revoked") or obj.get("x_mitre_deprecated")):
                continue
            attack_id = external_id(obj) or ""
            names = [obj.get("name", "")] + list(self._aliases(obj))
            lowered = [name.lower() for name in names]
            if needle == attack_id.lower() or needle in lowered:
                score = 0
            elif any(name.startswith(needle) for name in lowered):
                score = 1
            elif any(needle in name for name in lowered):
                score = 2
            elif needle in (obj.get("description") or "").lower():
                score = 3
            else:
                continue
            scored.append((score, attack_id, obj))
        scored.sort(key=lambda item: (item[0], item[1]))
        return [self._build_threat(obj) for _, _, obj in scored[:limit]]

    def get_threat(self, query: str, kind: Optional[str] = None,
                   with_campaigns: bool = False) -> ThreatProfile:
        """Resolve a group/software/campaign by ATT&CK ID, exact name or alias.

        ``--group "Cozy Bear"`` and ``--group G0016`` both reach APT29.  Fuzzy
        matches are offered as suggestions, never silently picked.
        """
        needle = (query or "").strip()
        if not needle:
            raise ThreatNotFoundError("No group, software or campaign given")

        if THREAT_ID_RE.match(needle):
            expected_kind = _KIND_BY_PREFIX[needle[0].upper()]
            if kind and kind != expected_kind:
                raise ThreatNotFoundError(f"{needle.upper()} is a {expected_kind} ID, not a {kind} ID")
            obj = self._by_attack_id.get(needle.upper())
            if obj is None or obj.get("type") not in THREAT_KINDS[expected_kind]:
                raise ThreatNotFoundError(f"{needle.upper()} is not in this ATT&CK bundle ({self.source})")
            return self._follow_threat_revocation(obj, with_campaigns)

        lowered = needle.lower()
        exact = [
            obj for obj in self._threat_objects(kind)
            if lowered == (obj.get("name") or "").lower()
            or lowered in (alias.lower() for alias in self._aliases(obj))
        ]
        active = [obj for obj in exact if not (obj.get("revoked") or obj.get("x_mitre_deprecated"))]
        if len(active) == 1 or (not active and len(exact) == 1):
            return self._follow_threat_revocation((active or exact)[0], with_campaigns)
        if len(active) > 1:
            options = ", ".join(f"{external_id(obj)} {obj.get('name')}" for obj in active)
            raise ThreatNotFoundError(f"'{needle}' is ambiguous - it matches {options}. Use the ATT&CK ID.")

        suggestions = self.search_threats(needle, kind, limit=5)
        hint = ("Did you mean: " + ", ".join(p.label for p in suggestions)) if suggestions else \
            "Try `search --groups <name>` to look it up."
        raise ThreatNotFoundError(f"No {kind or 'group, software or campaign'} named '{needle}'. {hint}")

    def _follow_threat_revocation(self, obj: dict[str, Any], with_campaigns: bool) -> ThreatProfile:
        if obj.get("revoked"):
            target = self._revoked_by.get(obj["id"])
            if target and target in self._by_stix_id:
                replacement = self._by_stix_id[target]
                LOG.warning("%s was revoked in favour of %s", external_id(obj), external_id(replacement))
                return self._build_threat(replacement, with_campaigns)
        return self._build_threat(obj, with_campaigns)

    def _current_technique_obj(self, stix_id: str) -> Optional[dict[str, Any]]:
        """Follow revocation chains so procedures point at live technique IDs."""
        seen: set[str] = set()
        obj = self._by_stix_id.get(stix_id)
        while obj is not None and obj.get("revoked") and obj["id"] not in seen:
            seen.add(obj["id"])
            target = self._revoked_by.get(obj["id"])
            obj = self._by_stix_id.get(target) if target else None
        if obj is None or obj.get("x_mitre_deprecated") or obj.get("revoked"):
            return None
        return obj

    def _procedures(self, user_stix_id: str, via: str = "") -> list[Procedure]:
        procedures: list[Procedure] = []
        for relationship in self._uses.get(user_stix_id, []):
            technique = self._current_technique_obj(relationship["target_ref"])
            if technique is None:
                continue
            procedures.append(Procedure(
                technique_id=external_id(technique) or "",
                technique_name=technique.get("name", ""),
                description=clean_text(relationship.get("description")),
                relationship_id=relationship["id"],
                via=via,
            ))
        return procedures

    def _build_threat(self, obj: dict[str, Any], with_campaigns: bool = False) -> ThreatProfile:
        kind = _KIND_BY_STIX_TYPE[obj["type"]]
        procedures = self._procedures(obj["id"])
        campaign_ids: list[str] = []
        for campaign_ref in self._attributed.get(obj["id"], []):
            campaign = self._by_stix_id.get(campaign_ref)
            if not campaign or campaign.get("revoked") or campaign.get("x_mitre_deprecated"):
                continue
            campaign_id = external_id(campaign) or ""
            campaign_ids.append(campaign_id)
            if with_campaigns:
                procedures.extend(self._procedures(campaign_ref, via=campaign_id))
        procedures.sort(key=lambda p: (p.technique_id, p.via))
        return ThreatProfile(
            id=external_id(obj) or "",
            stix_id=obj["id"],
            stix_type=obj["type"],
            kind=kind,
            name=obj.get("name", ""),
            aliases=tuple(alias for alias in self._aliases(obj) if alias != obj.get("name")),
            description=clean_text(obj.get("description")),
            url=attack_url(obj),
            created=str(obj.get("created") or ""),
            modified=str(obj.get("modified") or ""),
            procedures=tuple(procedures),
            campaigns=tuple(sorted(campaign_ids)),
            platforms=tuple(obj.get("x_mitre_platforms") or ()),
        )

    # -- construction of the rich objects ---------------------------------- #
    def _build_technique(self, obj: dict[str, Any]) -> Technique:
        stix_id = obj["id"]
        attack_id = external_id(obj) or ""
        parent_id = parent_name = None
        parent_ref = self._subtechnique_parent.get(stix_id)
        if parent_ref and parent_ref in self._by_stix_id:
            parent = self._by_stix_id[parent_ref]
            parent_id, parent_name = external_id(parent), parent.get("name")
        elif "." in attack_id:
            parent_id = attack_id.split(".", 1)[0]
            parent_obj = self._by_attack_id.get(parent_id)
            parent_name = parent_obj.get("name") if parent_obj else None

        revoked_by = None
        if obj.get("revoked"):
            target = self._revoked_by.get(stix_id)
            if target and target in self._by_stix_id:
                revoked_by = external_id(self._by_stix_id[target])

        mitigations = tuple(
            sorted(
                {
                    self._by_stix_id[ref].get("name", "")
                    for ref in self._mitigates.get(stix_id, [])
                    if ref in self._by_stix_id
                }
                - {""}
            )
        )

        return Technique(
            id=attack_id,
            stix_id=stix_id,
            name=obj.get("name", attack_id),
            description=clean_text(obj.get("description")),
            url=attack_url(obj),
            platforms=tuple(obj.get("x_mitre_platforms") or ()),
            tactics=tuple(
                phase.get("phase_name", "")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ),
            is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
            parent_id=parent_id,
            parent_name=parent_name,
            version=str(obj.get("x_mitre_version") or ""),
            created=str(obj.get("created") or ""),
            modified=str(obj.get("modified") or ""),
            deprecated=bool(obj.get("x_mitre_deprecated")),
            revoked=bool(obj.get("revoked")),
            revoked_by=revoked_by,
            detection_strategies=self._detection_strategies_for(stix_id),
            legacy_detection=clean_text(obj.get("x_mitre_detection")),
            legacy_data_sources=tuple(obj.get("x_mitre_data_sources") or ()),
            references=tuple(
                (ref.get("source_name", ""), ref.get("url", ""))
                for ref in obj.get("external_references", [])
                if ref.get("url")
            ),
            kill_chain_phases=tuple(obj.get("kill_chain_phases") or ()),
            mitigations=mitigations,
            detects_ref_count=len(self._detects.get(stix_id, [])),
        )

    def _detection_strategies_for(self, technique_stix_id: str) -> tuple[DetectionStrategy, ...]:
        strategies: list[DetectionStrategy] = []
        for strategy_ref in self._detects.get(technique_stix_id, []):
            obj = self._by_stix_id.get(strategy_ref)
            if not obj or obj.get("type") != "x-mitre-detection-strategy":
                continue
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue
            analytics = tuple(
                self._build_analytic(ref) for ref in obj.get("x_mitre_analytic_refs", [])
                if ref in self._by_stix_id
            )
            strategies.append(
                DetectionStrategy(
                    id=external_id(obj) or "",
                    stix_id=obj["id"],
                    name=obj.get("name", ""),
                    analytics=tuple(a for a in analytics if a is not None),
                    url=attack_url(obj),
                )
            )
        strategies.sort(key=lambda s: s.id)
        return tuple(strategies)

    def _build_analytic(self, analytic_ref: str) -> Optional[Analytic]:
        obj = self._by_stix_id.get(analytic_ref)
        if not obj or obj.get("type") != "x-mitre-analytic":
            return None
        log_sources = []
        for entry in obj.get("x_mitre_log_source_references", []):
            component = self._by_stix_id.get(entry.get("x_mitre_data_component_ref", ""), {})
            data_source = None
            source_ref = component.get("x_mitre_data_source_ref")
            if source_ref and source_ref in self._by_stix_id:
                data_source = self._by_stix_id[source_ref].get("name")
            channel = entry.get("channel")
            log_sources.append(
                LogSourceRef(
                    name=entry.get("name", ""),
                    channel=None if channel in (None, "", "None") else str(channel),
                    data_component=component.get("name"),
                    data_source=data_source,
                )
            )
        return Analytic(
            id=external_id(obj) or "",
            stix_id=obj["id"],
            name=obj.get("name", ""),
            description=clean_text(obj.get("description")),
            platforms=tuple(obj.get("x_mitre_platforms") or ()),
            log_sources=tuple(log_sources),
            mutable_elements=tuple(
                (element.get("field", ""), clean_text(element.get("description")))
                for element in obj.get("x_mitre_mutable_elements", [])
                if element.get("field")
            ),
            url=attack_url(obj),
        )

    # -- metadata ---------------------------------------------------------- #
    def metadata(self) -> dict[str, Any]:
        meta_path = Path(self.source).parent / META_FILENAME
        meta: dict[str, Any] = {}
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                meta = {}
        meta.setdefault("version", self.version)
        meta["object_count"] = len(self._objects)
        meta["path"] = self.source
        meta["technique_count"] = len(self.technique_ids())
        meta["detection_strategy_count"] = self.count("x-mitre-detection-strategy")
        meta["analytic_count"] = self.count("x-mitre-analytic")
        return meta


# --------------------------------------------------------------------------- #
# Small helpers shared with the rest of the package
# --------------------------------------------------------------------------- #
def external_id(obj: dict[str, Any], source_name: str = "mitre-attack") -> Optional[str]:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == source_name and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def attack_url(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return str(ref["url"])
    return ""


def pick_platform(technique: Technique, requested: Optional[str] = None) -> Optional[str]:
    """Resolve the platform to generate for, case-insensitively."""
    if requested:
        for platform in technique.platforms:
            if platform.lower() == requested.lower():
                return platform
        return requested
    return technique.platforms[0] if technique.platforms else None
