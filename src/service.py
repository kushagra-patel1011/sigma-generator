"""One service layer shared by the command line and the web UI.

Both front ends call the same functions here, so a rule generated in the
browser is byte-for-byte the rule the CLI would have written.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .attack_fetcher import THREAT_ID_RE, AttackDataset, Technique, ThreatProfile
from .mappings import resolve_telemetry
from .packs import DetectionPack, build_pack
from .sigma_generator import (
    ChainRule,
    SigmaRule,
    SigmaRuleGenerator,
    validate_sigma_text,
    validate_with_pysigma,
)
from .sigmahq import CoverageReport, SigmaHQIndex, assess_coverage, default_index_path
from .stix_builder import BundleOptions, build_bundle, validate_bundle
from .utils import (
    LOG,
    DataUnavailableError,
    FullyCoveredError,
    InsufficientEvidenceError,
    SigmaGeneratorError,
    UnmappableTechniqueError,
    env_int,
    env_str,
    first_sentences,
)


# --------------------------------------------------------------------------- #
# Options and results
# --------------------------------------------------------------------------- #
@dataclass
class GenerateOptions:
    platform: Optional[str] = None
    analytic: Optional[str] = None
    all_analytics: bool = False
    max_rules: int = 0
    chains: bool = False
    gaps_only: bool = False
    with_campaigns: bool = False
    author: Optional[str] = None
    status: Optional[str] = None
    level: Optional[str] = None
    tlp: Optional[str] = None
    template: Optional[str] = None
    deterministic: bool = False
    keep_revoked: bool = False
    strict: bool = False
    include_skeletons: bool = False


@dataclass
class TechniqueResult:
    """Everything one ``generate`` call produced for one technique ID."""

    requested_id: str
    technique: Optional[Technique] = None
    rules: list[SigmaRule] = field(default_factory=list)
    chains: list[ChainRule] = field(default_factory=list)
    coverage: Optional[CoverageReport] = None
    bundle: Optional[dict[str, Any]] = None
    status: str = "generated"          # generated | covered | insufficient | unmappable | error
    reason: str = ""
    warnings: list[str] = field(default_factory=list)
    problems: dict[str, list[str]] = field(default_factory=dict)   # filename -> validation errors

    @property
    def ok(self) -> bool:
        return bool(self.rules or self.chains)


# --------------------------------------------------------------------------- #
# Workspace
# --------------------------------------------------------------------------- #
class Workspace:
    """Lazily loaded ATT&CK dataset and SigmaHQ index."""

    def __init__(self, data_path: Optional[str] = None, sigmahq_path: Optional[str] = None,
                 offline: bool = False) -> None:
        self.data_path = data_path
        self.sigmahq_path = sigmahq_path
        self.offline = offline
        self._dataset: Optional[AttackDataset] = None
        self._sigmahq: Optional[SigmaHQIndex] = None

    @property
    def dataset(self) -> AttackDataset:
        if self._dataset is None:
            self._dataset = AttackDataset.load(
                path=self.data_path, offline=self.offline, timeout=env_int("ATTACK_HTTP_TIMEOUT", 60)
            )
        return self._dataset

    def sigmahq(self, required: bool = True) -> Optional[SigmaHQIndex]:
        """The SigmaHQ index; downloads it on first use unless offline."""
        if self._sigmahq is None:
            try:
                self._sigmahq = SigmaHQIndex.load(self.sigmahq_path, offline=self.offline)
            except DataUnavailableError:
                if required:
                    raise
                return None
        return self._sigmahq

    def sigmahq_available(self) -> bool:
        return self._sigmahq is not None or default_index_path(self.sigmahq_path).is_file()

    def coverage_index(self, required: bool) -> Optional[SigmaHQIndex]:
        """The index when gap analysis was asked for (downloading if needed), or
        when it is already cached locally - never a surprise download otherwise."""
        if required:
            return self.sigmahq(required=True)
        return self.sigmahq(required=False) if self.sigmahq_available() else None

    # -- factories ---------------------------------------------------------- #
    def generator(self, options: GenerateOptions) -> SigmaRuleGenerator:
        return SigmaRuleGenerator(
            author=options.author or env_str("SIGMA_AUTHOR", "") or None,
            status=options.status or env_str("SIGMA_STATUS", "") or None,
            level=options.level,
            deterministic=options.deterministic,
            template_path=options.template,
            attack_version=self.dataset.version,
        )

    @staticmethod
    def bundle_options(options: GenerateOptions, generator: SigmaRuleGenerator) -> BundleOptions:
        return BundleOptions(
            identity_name=env_str("STIX_IDENTITY_NAME", generator.author),
            tlp=options.tlp or env_str("STIX_TLP", "amber"),
            deterministic=options.deterministic,
        )

    # -- queries ------------------------------------------------------------ #
    def resolve_threat(self, query: str, kind: Optional[str] = None,
                       with_campaigns: bool = False) -> ThreatProfile:
        return self.dataset.get_threat(query, kind, with_campaigns=with_campaigns)

    def is_threat_id(self, value: str) -> bool:
        return bool(THREAT_ID_RE.match(value.strip()))

    # -- generation ----------------------------------------------------------- #
    def generate_technique(self, technique_id: str, options: GenerateOptions,
                           generator: Optional[SigmaRuleGenerator] = None,
                           with_bundle: bool = True) -> TechniqueResult:
        generator = generator or self.generator(options)
        result = TechniqueResult(requested_id=technique_id.strip().upper())
        try:
            technique = self.dataset.get_technique(result.requested_id)
        except SigmaGeneratorError as exc:
            result.status, result.reason = "error", str(exc)
            return result

        if technique.revoked and technique.revoked_by and not options.keep_revoked:
            result.warnings.append(
                f"{technique.id} was revoked in favour of {technique.revoked_by} - generating for "
                f"{technique.revoked_by} (use --keep-revoked to generate for the old ID)"
            )
            technique = self.dataset.get_technique(technique.revoked_by)
        elif technique.revoked:
            result.warnings.append(f"{technique.id} is revoked in ATT&CK {self.dataset.version}")
        elif technique.deprecated:
            result.warnings.append(f"{technique.id} is deprecated in ATT&CK {self.dataset.version}")
        result.technique = technique

        index = self.coverage_index(options.gaps_only)
        if index is not None:
            result.coverage = assess_coverage(technique, index)

        try:
            result.rules = generator.generate(
                technique,
                platform=options.platform,
                analytic_id=options.analytic,
                all_analytics=options.all_analytics,
                max_rules=options.max_rules,
                skip_mapping=result.coverage.is_covered if (options.gaps_only and result.coverage) else None,
                include_skeletons=options.include_skeletons,
            )
        except FullyCoveredError as exc:
            result.status, result.reason = "covered", str(exc)
        except InsufficientEvidenceError as exc:
            result.status, result.reason = "insufficient", str(exc)
        except UnmappableTechniqueError as exc:
            result.status, result.reason = "unmappable", str(exc)

        if options.chains and result.status != "unmappable":
            result.chains = generator.generate_correlations(
                technique, platform=options.platform, analytic_id=options.analytic,
                all_analytics=options.all_analytics,
            )
            if not result.chains:
                result.warnings.append(
                    f"No correlation rule for {technique.id}: no ATT&CK analytic names two or more log "
                    "sources with distinct behavioural content, or describes volume over a broad event."
                )

        for rule in list(result.rules) + list(result.chains):
            problems = validate_sigma_text(rule.to_yaml(include_banner=False))
            if options.strict:
                problems += validate_with_pysigma(rule.to_yaml(include_banner=False))[1]
            if problems:
                result.problems[rule.filename()] = problems

        if with_bundle and result.ok:
            result.bundle = build_bundle(result.rules, technique, self.bundle_options(options, generator),
                                         chains=result.chains)
            bundle_problems = validate_bundle(result.bundle)
            if bundle_problems:
                result.problems["bundle"] = bundle_problems
        return result

    def build_pack(self, query: str, kind: Optional[str], options: GenerateOptions,
                   generator: Optional[SigmaRuleGenerator] = None) -> DetectionPack:
        profile = self.resolve_threat(query, kind, with_campaigns=options.with_campaigns)
        index = self.coverage_index(options.gaps_only)
        return build_pack(
            self.dataset,
            generator or self.generator(options),
            profile,
            chains=options.chains,
            sigmahq=index,
            gaps_only=options.gaps_only,
            platform=options.platform,
            with_campaigns=options.with_campaigns,
            include_skeletons=options.include_skeletons,
        )

    # -- serialisation for JSON consumers ------------------------------------- #
    def technique_dict(self, technique: Technique, include_coverage: bool = False) -> dict[str, Any]:
        payload = technique_as_dict(technique, self.dataset.version)
        if include_coverage:
            index = self.coverage_index(required=False)
            payload["sigmahq"] = assess_coverage(technique, index).to_dict() if index else None
        return payload

    def threat_dict(self, profile: ThreatProfile) -> dict[str, Any]:
        return {
            "id": profile.id,
            "name": profile.name,
            "kind": profile.kind,
            "aliases": list(profile.aliases),
            "url": profile.url,
            "description": first_sentences(profile.description, 3, 700),
            "campaigns": list(profile.campaigns),
            "techniques": [
                {
                    "id": technique_id,
                    "name": profile.procedures_for(technique_id)[0].technique_name,
                    "procedures": [p.description for p in profile.procedures_for(technique_id)],
                }
                for technique_id in profile.technique_ids
            ],
        }


def technique_as_dict(technique: Technique, attack_version: str) -> dict[str, Any]:
    return {
        "id": technique.id,
        "name": technique.name,
        "stix_id": technique.stix_id,
        "url": technique.url,
        "tactics": list(technique.tactics),
        "platforms": list(technique.platforms),
        "is_subtechnique": technique.is_subtechnique,
        "parent": {"id": technique.parent_id, "name": technique.parent_name} if technique.parent_id else None,
        "version": technique.version,
        "modified": technique.modified,
        "deprecated": technique.deprecated,
        "revoked": technique.revoked,
        "revoked_by": technique.revoked_by,
        "attack_version": attack_version,
        "description": technique.description,
        "mitigations": list(technique.mitigations),
        "detection_strategies": [
            {
                "id": strategy.id,
                "name": strategy.name,
                "url": strategy.url,
                "analytics": [
                    {
                        "id": analytic.id,
                        "platforms": list(analytic.platforms),
                        "description": analytic.description,
                        "log_sources": [
                            _log_source_dict(log_source, analytic.platforms[0] if analytic.platforms else None)
                            for log_source in analytic.log_sources
                        ],
                        "tuning_knobs": [
                            {"field": name, "description": description}
                            for name, description in analytic.mutable_elements
                        ],
                    }
                    for analytic in strategy.analytics
                ],
            }
            for strategy in technique.detection_strategies
        ],
    }


def _log_source_dict(log_source, platform: Optional[str]) -> dict[str, Any]:
    mapping = resolve_telemetry(log_source.name, log_source.channel, log_source.data_component, platform)
    return {
        "name": log_source.name,
        "channel": log_source.channel,
        "data_component": log_source.data_component,
        "sigma_logsource": mapping.logsource.as_dict(),
        "mappable": mapping.is_usable,
        "confidence": mapping.confidence,
    }
