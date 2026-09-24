"""Wrap generated Sigma rules in a STIX 2.1 bundle.

One bundle carries, for each rule:

* an ``indicator`` whose ``pattern`` is the Sigma rule and whose
  ``pattern_type`` is ``sigma`` (a value in the STIX 2.1 ``pattern-type-ov``),
* a faithful subset of the ATT&CK ``attack-pattern`` it was written for, keeping
  MITRE's own STIX id so a TIP de-duplicates against its ATT&CK feed,
* an ``indicator --indicates--> attack-pattern`` relationship, which is the
  relationship the STIX 2.1 specification defines for this pairing,

plus the author ``identity`` and the TLP ``marking-definition`` every object
references.

The Sigma rule's UUID is reused as the indicator's UUID, so a rule and its
indicator are traceable to each other without a lookup table.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence

from . import __version__
from .attack_fetcher import Technique, ThreatProfile
from .sigma_generator import ChainRule, SigmaRule
from .utils import LOG, first_sentences, utcnow_iso

STIX_VERSION = "2.1"
SIGMA_SPEC_VERSION = "2.0"

#: Namespace for deterministic (UUIDv5) STIX identifiers.
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

#: TLP v1 marking definitions, quoted verbatim from the STIX 2.1 specification.
TLP_MARKINGS: dict[str, dict[str, Any]] = {
    "white": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:WHITE",
        "definition": {"tlp": "white"},
    },
    "green": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:GREEN",
        "definition": {"tlp": "green"},
    },
    "amber": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:AMBER",
        "definition": {"tlp": "amber"},
    },
    "red": {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:RED",
        "definition": {"tlp": "red"},
    },
}
#: TLP 2.0 dropped WHITE in favour of CLEAR; accept the new spelling.
TLP_ALIASES = {"clear": "white"}

VALID_TLP = tuple(TLP_MARKINGS) + tuple(TLP_ALIASES)


@dataclass
class BundleOptions:
    """Knobs for :func:`build_bundle`."""

    identity_name: str = "sigma-generator"
    tlp: str = "amber"
    deterministic: bool = False
    include_attack_pattern: bool = True
    indicator_types: Sequence[str] = ("anomalous-activity",)
    include_banner_in_pattern: bool = False


# --------------------------------------------------------------------------- #
# Identifier helpers
# --------------------------------------------------------------------------- #
def _stix_id(stix_type: str, seed: Optional[str] = None, deterministic: bool = False) -> str:
    if deterministic and seed:
        return f"{stix_type}--{uuid.uuid5(STIX_NAMESPACE, seed)}"
    return f"{stix_type}--{uuid.uuid4()}"


def _identity_id(name: str) -> str:
    """Identities are always deterministic so repeated runs share one author."""
    return f"identity--{uuid.uuid5(STIX_NAMESPACE, 'identity:' + name)}"


def normalise_tlp(value: str) -> str:
    key = (value or "amber").strip().lower()
    key = TLP_ALIASES.get(key, key)
    if key not in TLP_MARKINGS:
        raise ValueError(f"Unknown TLP '{value}'. Choose from: clear/white, green, amber, red")
    return key


# --------------------------------------------------------------------------- #
# Object builders
# --------------------------------------------------------------------------- #
def build_identity(name: str, timestamp: str) -> dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": STIX_VERSION,
        "id": _identity_id(name),
        "created": timestamp,
        "modified": timestamp,
        "name": name,
        "description": (
            f"Automated draft detection authoring (sigma-generator v{__version__}). "
            "Rules in this bundle are machine-generated from MITRE ATT&CK and "
            "require analyst review before deployment."
        ),
        "identity_class": "system",
    }


def build_attack_pattern(technique: Technique, marking_ref: str) -> dict[str, Any]:
    """A faithful subset of MITRE's own attack-pattern object.

    The STIX id, timestamps, name, description and kill chain phases are copied
    from ATT&CK unchanged so that a consumer already carrying the ATT&CK feed
    sees the same object rather than a competing one.
    """
    external_references: list[dict[str, str]] = [{
        "source_name": "mitre-attack",
        "external_id": technique.id,
        "url": technique.url,
    }]
    for source_name, url in technique.references:
        if source_name == "mitre-attack" or not url:
            continue
        external_references.append({"source_name": source_name, "url": url})
        if len(external_references) >= 6:
            break

    attack_pattern: dict[str, Any] = {
        "type": "attack-pattern",
        "spec_version": STIX_VERSION,
        "id": technique.stix_id,
        "created": technique.created or utcnow_iso(),
        "modified": technique.modified or utcnow_iso(),
        "name": technique.name,
        "description": technique.description,
        "external_references": external_references,
        "object_marking_refs": [marking_ref],
    }
    if technique.kill_chain_phases:
        attack_pattern["kill_chain_phases"] = [dict(phase) for phase in technique.kill_chain_phases]
    if technique.platforms:
        attack_pattern["x_mitre_platforms"] = list(technique.platforms)
    if technique.is_subtechnique:
        attack_pattern["x_mitre_is_subtechnique"] = True
    return attack_pattern


def build_indicator(rule: SigmaRule | ChainRule, technique: Technique, identity_ref: str,
                    marking_ref: str, timestamp: str,
                    options: Optional[BundleOptions] = None) -> dict[str, Any]:
    """Build the ``indicator`` carrying one Sigma rule (or correlation file) as its pattern."""
    options = options or BundleOptions()
    provenance = rule.provenance
    is_chain = isinstance(rule, ChainRule)

    description_parts = [
        f"Draft Sigma {'correlation rule' if is_chain else 'rule'} for {technique.id} ({technique.name}).",
        f"Log source{'s' if is_chain else ''}: {provenance.logsource_label} "
        f"(resolved from {provenance.telemetry_source}).",
    ]
    if is_chain and rule.kind == "count":
        condition = rule.correlation["condition"]
        counted = f"distinct {condition['field']} values" if "field" in condition else "matching events"
        description_parts.append(
            f"Fires when {condition['gte']} or more {counted} occur per {', '.join(rule.correlation['group-by'])} "
            f"within {rule.correlation['timespan']}; the pattern holds the correlation and its base rule."
        )
    elif is_chain:
        description_parts.append(
            f"Fires when {len(rule.steps)} behaviours occur together within "
            f"{rule.correlation['timespan']}; the pattern holds the correlation and its base rules."
        )
    description_parts.append(f"Rule quality: {rule.quality.label}.")
    if provenance.threat_label:
        description_parts.append(f"Built for the {provenance.threat_label} detection pack.")
    if provenance.strategy_id:
        description_parts.append(
            f"Derived from ATT&CK detection strategy {provenance.strategy_id}"
            + (f" / analytic {provenance.analytic_id}" if provenance.analytic_id else "")
            + "."
        )
    description_parts.append(
        "Machine-generated draft - validate against real telemetry before deployment."
    )

    external_references = [{
        "source_name": "mitre-attack",
        "external_id": technique.id,
        "url": technique.url,
    }]
    for reference in rule.references:
        if reference == technique.url or not reference.startswith("http"):
            continue
        source_name = "mitre-attack" if "attack.mitre.org" in reference else "reference"
        external_references.append({"source_name": source_name, "url": reference})
        if len(external_references) >= 6:
            break

    labels = ["sigma-correlation-rule" if is_chain else "sigma-rule", "draft",
              f"attack.{technique.id.lower()}", f"sigma-level.{rule.level}", f"quality.{rule.quality.tier}"]
    if provenance.platform:
        labels.append(f"platform.{provenance.platform.lower().replace(' ', '-')}")

    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": STIX_VERSION,
        # The Sigma rule UUID is reused so rule <-> indicator stays traceable.
        "id": f"indicator--{rule.id}",
        "created_by_ref": identity_ref,
        "created": timestamp,
        "modified": timestamp,
        "name": rule.title,
        "description": " ".join(description_parts),
        "indicator_types": list(options.indicator_types),
        "pattern": rule.to_yaml(include_banner=options.include_banner_in_pattern),
        "pattern_type": "sigma",
        "pattern_version": SIGMA_SPEC_VERSION,
        "valid_from": timestamp,
        "labels": labels,
        # STIX confidence (0-100) carries how certain we are that the telemetry
        # mapping behind this rule is right - see mappings.resolve_telemetry.
        "confidence": int(round(provenance.confidence * 100)),
        "external_references": external_references,
        "object_marking_refs": [marking_ref],
    }
    if technique.kill_chain_phases:
        indicator["kill_chain_phases"] = [dict(phase) for phase in technique.kill_chain_phases]
    return indicator


def build_relationship(indicator_id: str, target_id: str, identity_ref: str, marking_ref: str,
                       timestamp: str, deterministic: bool = False,
                       relationship_type: str = "indicates",
                       description: str = "") -> dict[str, Any]:
    relationship = {
        "type": "relationship",
        "spec_version": STIX_VERSION,
        "id": _stix_id("relationship", f"{relationship_type}:{indicator_id}:{target_id}", deterministic),
        "created_by_ref": identity_ref,
        "created": timestamp,
        "modified": timestamp,
        "relationship_type": relationship_type,
        "source_ref": indicator_id,
        "target_ref": target_id,
        "object_marking_refs": [marking_ref],
    }
    if description:
        relationship["description"] = description
    return relationship


# --------------------------------------------------------------------------- #
# Bundle assembly
# --------------------------------------------------------------------------- #
def build_bundle(rules: Sequence[SigmaRule], technique: Technique,
                 options: Optional[BundleOptions] = None,
                 chains: Sequence[ChainRule] = ()) -> dict[str, Any]:
    """Assemble a STIX 2.1 bundle for one technique's generated rules and chains."""
    if not rules and not chains:
        raise ValueError("build_bundle needs at least one rule")

    options = options or BundleOptions()
    tlp_key = normalise_tlp(options.tlp)
    marking = TLP_MARKINGS[tlp_key]
    timestamp = utcnow_iso()

    identity = build_identity(options.identity_name, timestamp)
    objects: list[dict[str, Any]] = [marking, identity]

    if options.include_attack_pattern:
        objects.append(build_attack_pattern(technique, marking["id"]))

    objects.extend(_indicator_objects(list(rules) + list(chains), technique, identity["id"],
                                      marking["id"], timestamp, options))

    bundle_seed = f"bundle:{technique.id}:" + ",".join(rule.id for rule in list(rules) + list(chains))
    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle", bundle_seed, options.deterministic),
        "objects": objects,
    }
    LOG.info("Built STIX bundle with %d object(s) for %s", len(objects), technique.id)
    return bundle


def _indicator_objects(rules: Sequence[SigmaRule | ChainRule], technique: Technique, identity_ref: str,
                       marking_ref: str, timestamp: str, options: BundleOptions) -> list[dict[str, Any]]:
    """Indicator + ``indicates`` relationship for every rule."""
    objects: list[dict[str, Any]] = []
    for rule in rules:
        indicator = build_indicator(rule, technique, identity_ref, marking_ref, timestamp, options)
        objects.append(indicator)
        if options.include_attack_pattern:
            kind = "correlation rule" if isinstance(rule, ChainRule) else "rule"
            objects.append(
                build_relationship(
                    indicator["id"], technique.stix_id, identity_ref, marking_ref, timestamp,
                    deterministic=options.deterministic,
                    description=f"Draft Sigma {kind} detecting {technique.id} ({technique.name}).",
                )
            )
    return objects


# --------------------------------------------------------------------------- #
# Detection packs (group / software / campaign)
# --------------------------------------------------------------------------- #
_REPORT_TYPES = {"intrusion-set": "threat-actor", "malware": "malware", "tool": "tool", "campaign": "campaign"}


def build_threat_object(profile: ThreatProfile, raw: Optional[dict[str, Any]], marking_ref: str) -> dict[str, Any]:
    """A faithful subset of MITRE's group/software/campaign object (same STIX id)."""
    raw = raw or {}
    threat: dict[str, Any] = {
        "type": profile.stix_type,
        "spec_version": STIX_VERSION,
        "id": profile.stix_id,
        "created": profile.created or utcnow_iso(),
        "modified": profile.modified or utcnow_iso(),
        "name": profile.name,
        "description": profile.description,
        "external_references": [{"source_name": "mitre-attack", "external_id": profile.id, "url": profile.url}],
        "object_marking_refs": [marking_ref],
    }
    if profile.stix_type in ("intrusion-set", "campaign") and raw.get("aliases"):
        threat["aliases"] = list(raw["aliases"])
    if profile.stix_type in ("malware", "tool") and raw.get("x_mitre_aliases"):
        threat["x_mitre_aliases"] = list(raw["x_mitre_aliases"])
    if profile.stix_type == "malware":
        threat["is_family"] = bool(raw.get("is_family", True))  # required by STIX 2.1
    for key in ("first_seen", "last_seen"):
        if raw.get(key):
            threat[key] = raw[key]
    return threat


def build_pack_bundle(profile: ThreatProfile,
                      entries: Sequence[tuple[Technique, Sequence[SigmaRule], Sequence[ChainRule]]],
                      raw_lookup: Any,
                      options: Optional[BundleOptions] = None) -> dict[str, Any]:
    """One bundle for a whole detection pack.

    Contents: the group/software/campaign, the techniques it uses (with MITRE's
    own ``uses`` relationships and procedure descriptions), an indicator per
    generated rule, and a ``report`` tying it together so a TIP shows the pack
    as a single browsable item.

    ``raw_lookup`` is anything with ``raw_object(stix_id)`` - normally the
    :class:`~src.attack_fetcher.AttackDataset`.
    """
    entries = [entry for entry in entries if entry[1] or entry[2]]
    if not entries:
        raise ValueError("build_pack_bundle needs at least one technique with a rule")

    options = options or BundleOptions()
    marking = TLP_MARKINGS[normalise_tlp(options.tlp)]
    timestamp = utcnow_iso()
    identity = build_identity(options.identity_name, timestamp)
    threat = build_threat_object(profile, raw_lookup.raw_object(profile.stix_id), marking["id"])
    objects: list[dict[str, Any]] = [marking, identity, threat]

    rule_ids: list[str] = []
    for technique, rules, chains in entries:
        objects.append(build_attack_pattern(technique, marking["id"]))
        for procedure in profile.procedures_for(technique.id):
            if procedure.via:
                continue  # inherited from a campaign; the campaign is not in this bundle
            raw = raw_lookup.raw_object(procedure.relationship_id) or {}
            # Keep MITRE's relationship id only while it still points at this
            # technique; a followed revocation gets an id of our own.
            same_target = raw.get("target_ref") == technique.stix_id
            objects.append({
                "type": "relationship",
                "spec_version": STIX_VERSION,
                "id": procedure.relationship_id if same_target else _stix_id(
                    "relationship", f"uses:{profile.stix_id}:{technique.stix_id}", True),
                "created": raw.get("created", timestamp) if same_target else timestamp,
                "modified": raw.get("modified", timestamp) if same_target else timestamp,
                "relationship_type": "uses",
                "source_ref": profile.stix_id,
                "target_ref": technique.stix_id,
                "description": procedure.description,
                "object_marking_refs": [marking["id"]],
            })
        objects.extend(_indicator_objects(list(rules) + list(chains), technique, identity["id"],
                                          marking["id"], timestamp, options))
        rule_ids.extend(rule.id for rule in list(rules) + list(chains))

    # De-duplicate (a technique can appear once per procedure) while keeping order.
    unique: dict[str, dict[str, Any]] = {}
    for obj in objects:
        unique.setdefault(obj["id"], obj)
    objects = list(unique.values())

    rule_total = sum(len(rules) for _, rules, _ in entries)
    chain_total = sum(len(chains) for _, _, chains in entries)
    report = {
        "type": "report",
        "spec_version": STIX_VERSION,
        "id": _stix_id("report", f"pack:{profile.id}:" + ",".join(sorted(rule_ids)), options.deterministic),
        "created_by_ref": identity["id"],
        "created": timestamp,
        "modified": timestamp,
        "name": f"Detection pack: {profile.label}",
        "description": (
            f"Draft Sigma detections for the {len(entries)} ATT&CK techniques attributed to "
            f"{profile.label} that could be expressed as Sigma: {rule_total} rule(s) and "
            f"{chain_total} correlation rule(s). Machine-generated - review before deployment."
        ),
        "report_types": [_REPORT_TYPES.get(profile.stix_type, "threat-report"), "indicator", "attack-pattern"],
        "published": timestamp,
        "object_refs": [obj["id"] for obj in objects if obj["type"] != "marking-definition"],
        "object_marking_refs": [marking["id"]],
    }
    objects.append(report)
    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle", f"pack-bundle:{profile.id}:" + ",".join(sorted(rule_ids)), options.deterministic),
        "objects": objects,
    }
    LOG.info("Built detection-pack bundle for %s with %d object(s)", profile.label, len(objects))
    return bundle


def merge_bundles(bundles: Iterable[dict[str, Any]], deterministic: bool = False) -> dict[str, Any]:
    """Combine per-technique bundles into one, de-duplicating shared objects."""
    objects: list[dict[str, Any]] = []
    seen: set[str] = set()
    for bundle in bundles:
        for obj in bundle.get("objects", []):
            object_id = obj.get("id", "")
            if object_id in seen:
                continue
            seen.add(object_id)
            objects.append(obj)
    seed = "bundle:merged:" + ",".join(sorted(seen))
    return {"type": "bundle", "id": _stix_id("bundle", seed, deterministic), "objects": objects}


def dump_bundle(bundle: dict[str, Any], indent: int = 2) -> str:
    return json.dumps(bundle, indent=indent, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
_REQUIRED_PROPERTIES: dict[str, tuple[str, ...]] = {
    "identity": ("name",),
    "attack-pattern": ("name",),
    "indicator": ("pattern", "pattern_type", "valid_from"),
    "relationship": ("relationship_type", "source_ref", "target_ref"),
    "marking-definition": ("definition_type",),
    "report": ("name", "published", "object_refs"),
    "intrusion-set": ("name",),
    "tool": ("name",),
    "campaign": ("name",),
    "malware": ("name",),
}

_ID_PATTERN = "--"


def validate_bundle(bundle: dict[str, Any]) -> list[str]:
    """Structural STIX 2.1 checks. Returns human-readable errors."""
    errors: list[str] = []
    if not isinstance(bundle, dict):
        return ["bundle is not a JSON object"]
    if bundle.get("type") != "bundle":
        errors.append("top-level object is not a STIX bundle")
    bundle_id = str(bundle.get("id", ""))
    if not bundle_id.startswith("bundle--"):
        errors.append("bundle id must start with 'bundle--'")

    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        return errors + ["bundle contains no objects"]

    identifiers: set[str] = set()
    for index, obj in enumerate(objects):
        if not isinstance(obj, dict):
            errors.append(f"object #{index} is not a JSON object")
            continue
        stix_type = obj.get("type", "")
        object_id = str(obj.get("id", ""))
        location = object_id or f"object #{index}"
        if not stix_type:
            errors.append(f"{location} has no type")
        if _ID_PATTERN not in object_id or not object_id.startswith(f"{stix_type}--"):
            errors.append(f"{location} has a malformed id for type '{stix_type}'")
        else:
            try:
                uuid.UUID(object_id.split("--", 1)[1])
            except ValueError:
                errors.append(f"{location} does not end in a valid UUID")
        if object_id in identifiers:
            errors.append(f"{location} appears more than once in the bundle")
        identifiers.add(object_id)

        # marking-definition objects are immutable and carry no `modified`.
        if stix_type not in ("marking-definition",):
            if obj.get("spec_version") != STIX_VERSION:
                errors.append(f"{location} is missing spec_version 2.1")
            for prop in ("created", "modified"):
                if not obj.get(prop):
                    errors.append(f"{location} is missing '{prop}'")

        for prop in _REQUIRED_PROPERTIES.get(stix_type, ()):
            if not obj.get(prop):
                errors.append(f"{location} is missing required property '{prop}'")

        if stix_type == "indicator" and obj.get("pattern_type") != "sigma":
            errors.append(f"{location} should declare pattern_type 'sigma'")
        if stix_type == "indicator":
            confidence = obj.get("confidence")
            if confidence is not None and not (isinstance(confidence, int) and 0 <= confidence <= 100):
                errors.append(f"{location} has a confidence outside 0-100")

    # Every reference must resolve inside the bundle.
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        location = obj.get("id", "object")
        references: list[str] = []
        for key in ("created_by_ref", "source_ref", "target_ref"):
            if obj.get(key):
                references.append(str(obj[key]))
        references.extend(str(ref) for ref in obj.get("object_marking_refs", []) or [])
        references.extend(str(ref) for ref in obj.get("object_refs", []) or [])
        if obj.get("type") == "malware" and not isinstance(obj.get("is_family"), bool):
            errors.append(f"{location} is missing the required boolean 'is_family'")
        for reference in references:
            if reference not in identifiers:
                errors.append(f"{location} references '{reference}', which is not in the bundle")

    return errors
