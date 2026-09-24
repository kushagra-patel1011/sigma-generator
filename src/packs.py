"""Detection packs: every detection for one ATT&CK group, software or campaign.

``generate --group APT29`` resolves the group, walks every technique ATT&CK
says it uses, and for each one builds a rule (mining the group's own procedure
examples first), optionally an attack-chain correlation rule, and optionally a
SigmaHQ coverage verdict.  The result is written as one folder: rules, a STIX
bundle with a ``report`` object, and a README summarising the pack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import __version__
from .attack_fetcher import AttackDataset, Procedure, Technique, ThreatProfile
from .sigma_generator import ChainRule, SigmaRule, SigmaRuleGenerator, ThreatContext
from .sigmahq import CoverageReport, SigmaHQIndex, assess_coverage
from .stix_builder import BundleOptions, build_pack_bundle, dump_bundle, validate_bundle
from .utils import (
    LOG,
    FullyCoveredError,
    InsufficientEvidenceError,
    SigmaGeneratorError,
    UnmappableTechniqueError,
    first_sentences,
    slugify,
    utcnow_iso,
    write_text,
)

STATUS_GENERATED = "generated"
STATUS_COVERED = "covered by SigmaHQ"
STATUS_UNMAPPABLE = "unmappable"
STATUS_INSUFFICIENT = "insufficient evidence"
STATUS_ERROR = "error"

#: Quality tiers, strongest first, for summaries.
_TIERS = ("strong", "moderate", "weak", "placeholder")


@dataclass
class PackEntry:
    """The outcome for one technique in a pack."""

    technique_id: str
    technique_name: str
    tactics: tuple[str, ...]
    procedures: tuple[Procedure, ...]
    status: str
    technique: Optional[Technique] = None
    rules: list[SigmaRule] = field(default_factory=list)
    chains: list[ChainRule] = field(default_factory=list)
    coverage: Optional[CoverageReport] = None
    reason: str = ""


@dataclass
class DetectionPack:
    profile: ThreatProfile
    entries: list[PackEntry]
    attack_version: str
    sigmahq_release: Optional[str] = None
    with_campaigns: bool = False
    gaps_only: bool = False
    chains_requested: bool = False
    skeletons_included: bool = False
    generated_at: str = field(default_factory=utcnow_iso)

    @property
    def slug(self) -> str:
        return slugify(f"{self.profile.id} {self.profile.name}", 50)

    @property
    def generated(self) -> list[PackEntry]:
        return [entry for entry in self.entries if entry.rules or entry.chains]

    @property
    def rule_count(self) -> int:
        return sum(len(entry.rules) for entry in self.entries)

    @property
    def chain_count(self) -> int:
        return sum(len(entry.chains) for entry in self.entries)

    def count(self, status: str) -> int:
        return sum(1 for entry in self.entries if entry.status == status)

    def tier_counts(self) -> dict[str, int]:
        """How many rules and correlation rules fall in each quality tier."""
        counts = {tier: 0 for tier in _TIERS}
        for entry in self.entries:
            for rule in list(entry.rules) + list(entry.chains):
                counts[rule.quality.tier] += 1
        return counts

    # -- rendering ----------------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": {
                "id": self.profile.id, "name": self.profile.name, "kind": self.profile.kind,
                "aliases": list(self.profile.aliases), "url": self.profile.url,
                "campaigns": list(self.profile.campaigns),
                "description": first_sentences(self.profile.description, 3, 600),
            },
            "attack_version": self.attack_version,
            "sigmahq_release": self.sigmahq_release,
            "generated_at": self.generated_at,
            "options": {"with_campaigns": self.with_campaigns, "gaps_only": self.gaps_only,
                        "chains": self.chains_requested, "include_skeletons": self.skeletons_included},
            "summary": {
                "techniques": len(self.entries),
                "techniques_with_rules": len(self.generated),
                "rules": self.rule_count,
                "correlation_rules": self.chain_count,
                "covered_by_sigmahq": self.count(STATUS_COVERED),
                "insufficient_evidence": self.count(STATUS_INSUFFICIENT),
                "unmappable": self.count(STATUS_UNMAPPABLE),
                "errors": self.count(STATUS_ERROR),
                "quality": self.tier_counts(),
            },
            "techniques": [
                {
                    "id": entry.technique_id,
                    "name": entry.technique_name,
                    "tactics": list(entry.tactics),
                    "status": entry.status,
                    "reason": entry.reason,
                    "procedures": [p.description for p in entry.procedures],
                    "rules": [{"id": r.id, "title": r.title, "file": r.filename(), "level": r.level,
                               "logsource": r.provenance.logsource_label, "quality": r.quality.tier,
                               "confidence": r.provenance.confidence} for r in entry.rules],
                    "chains": [{"id": c.id, "title": c.title, "file": c.filename(), "level": c.level,
                                "kind": c.kind, "type": c.correlation["type"], "quality": c.quality.tier,
                                "steps": len(c.steps), "timespan": c.correlation["timespan"]}
                               for c in entry.chains],
                    "sigmahq": entry.coverage.to_dict() if entry.coverage else None,
                }
                for entry in self.entries
            ],
        }

    def to_markdown(self) -> str:
        profile = self.profile
        lines = [
            f"# Detection pack: {profile.name} ({profile.id})",
            "",
            f"Generated by sigma-generator v{__version__} on {self.generated_at[:10]} from MITRE ATT&CK "
            f"v{self.attack_version}" + (f" and SigmaHQ {self.sigmahq_release}" if self.sigmahq_release else "")
            + ".",
            "",
            "> Draft detections. Every rule was generated from ATT&CK data and must be reviewed and",
            "> tested against real telemetry before deployment.",
            "",
            f"**{profile.kind.title()}:** [{profile.name}]({profile.url})"
            + (f" - also known as {', '.join(profile.aliases[:8])}" if profile.aliases else ""),
            "",
            first_sentences(profile.description, 3, 700),
            "",
            "## Summary",
            "",
            "| | |",
            "|---|---|",
            f"| Techniques attributed by ATT&CK | {len(self.entries)} |",
            f"| Techniques with generated detections | {len(self.generated)} |",
            f"| Sigma rules | {self.rule_count} |",
            f"| Correlation rules (attack chains and count thresholds) | {self.chain_count} |",
        ]
        tiers = self.tier_counts()
        lines.append("| Quality: strong / moderate / weak"
                     + (" / skeleton" if self.skeletons_included else "") + " | "
                     + " / ".join(str(tiers[t]) for t in _TIERS if t != "placeholder" or self.skeletons_included)
                     + " |")
        if self.sigmahq_release:
            no_rules = sum(1 for e in self.entries if e.coverage and e.coverage.usable_sources
                           and not e.coverage.exact_rules)
            partial = sum(1 for e in self.entries if e.coverage and e.coverage.exact_rules and e.coverage.gaps)
            lines.append(f"| Techniques SigmaHQ has no rule for | {no_rules} |")
            lines.append(f"| Techniques where SigmaHQ misses some recommended telemetry | {partial} |")
            if self.gaps_only:
                lines.append(f"| Fully covered by SigmaHQ (skipped) | {self.count(STATUS_COVERED)} |")
        lines.append(f"| No concrete values in ATT&CK (no rule written) | {self.count(STATUS_INSUFFICIENT)} |")
        lines.append(f"| Not expressible as Sigma | {self.count(STATUS_UNMAPPABLE)} |")
        if self.with_campaigns and profile.campaigns:
            lines.append(f"| Includes techniques from campaigns | {', '.join(profile.campaigns)} |")

        lines += ["", "## Techniques", "",
                  "| Technique | Tactics | Rules | Correlations | SigmaHQ | Status |",
                  "|---|---|---|---|---|---|"]
        for entry in self.entries:
            rules = "<br>".join(f"`sigma/{rule.filename()}` ({rule.quality.tier})" for rule in entry.rules) or "-"
            chains = "<br>".join(f"`sigma/{chain.filename()}` ({chain.quality.tier})" for chain in entry.chains) or "-"
            if entry.coverage:
                sigmahq = f"{len(entry.coverage.exact_rules)} rule(s), {len(entry.coverage.gaps)} gap(s)"
            else:
                sigmahq = "-"
            lines.append(
                f"| [{entry.technique_id}](https://attack.mitre.org/techniques/"
                f"{entry.technique_id.replace('.', '/')}) {entry.technique_name} "
                f"| {', '.join(entry.tactics)} | {rules} | {chains} | {sigmahq} | {entry.status} |"
            )

        skipped = [entry for entry in self.entries
                   if entry.status in (STATUS_INSUFFICIENT, STATUS_UNMAPPABLE, STATUS_ERROR)]
        if skipped:
            lines += ["", "## Not generated", ""]
            for entry in skipped:
                lines.append(f"- **{entry.technique_id} {entry.technique_name}** - {entry.reason.splitlines()[0]}")

        lines += [
            "",
            "## Files",
            "",
            "- `sigma/` - one Sigma rule per technique; `mr_*.yml` files are correlation rules",
            "- Quality tiers: *strong* = two or more independent signals; *moderate* = one signal, review for",
            "  noise; *weak* = broad hunting rule tagged `detection.threat-hunting`",
            f"- `{self.slug}_bundle.json` - STIX 2.1 bundle: the {profile.kind}, its techniques and procedure",
            "  descriptions, one indicator per rule, and a `report` object tying the pack together",
            "- `pack.json` - the same summary in machine-readable form",
            "",
        ]
        return "\n".join(lines)


def context_for(profile: ThreatProfile, technique_id: str) -> ThreatContext:
    return ThreatContext(
        label=profile.label,
        url=profile.url,
        sigma_tag=profile.sigma_tag,
        procedures=tuple(p.description for p in profile.procedures_for(technique_id) if p.description),
        platforms=profile.platforms if profile.kind == "software" else (),
    )


def build_pack(
    dataset: AttackDataset,
    generator: SigmaRuleGenerator,
    profile: ThreatProfile,
    *,
    chains: bool = False,
    sigmahq: Optional[SigmaHQIndex] = None,
    gaps_only: bool = False,
    platform: Optional[str] = None,
    with_campaigns: bool = False,
    include_skeletons: bool = False,
) -> DetectionPack:
    """Generate detections for every technique ``profile`` uses."""
    if gaps_only and sigmahq is None:
        raise SigmaGeneratorError("--gaps-only needs the SigmaHQ index")

    entries: list[PackEntry] = []
    for technique_id in profile.technique_ids:
        procedures = profile.procedures_for(technique_id)
        try:
            technique = dataset.get_technique(technique_id)
        except SigmaGeneratorError as exc:
            entries.append(PackEntry(technique_id, procedures[0].technique_name, (), procedures,
                                     STATUS_ERROR, reason=str(exc)))
            continue

        entry = PackEntry(technique.id, technique.name, technique.tactics, procedures,
                          STATUS_GENERATED, technique=technique)
        context = context_for(profile, technique.id)
        coverage = assess_coverage(technique, sigmahq) if sigmahq else None
        entry.coverage = coverage

        try:
            entry.rules = generator.generate(
                technique, platform=platform, context=context,
                skip_mapping=coverage.is_covered if (gaps_only and coverage) else None,
                include_skeletons=include_skeletons,
            )
        except FullyCoveredError as exc:
            entry.status, entry.reason = STATUS_COVERED, str(exc)
        except InsufficientEvidenceError as exc:
            entry.status, entry.reason = STATUS_INSUFFICIENT, str(exc)
        except UnmappableTechniqueError as exc:
            entry.status, entry.reason = STATUS_UNMAPPABLE, str(exc)

        # Correlation rules are generated even when SigmaHQ covers the single events.
        if chains and entry.status != STATUS_UNMAPPABLE:
            entry.chains = generator.generate_correlations(technique, platform=platform, context=context)
            if entry.chains and entry.status in (STATUS_COVERED, STATUS_INSUFFICIENT):
                entry.reason += " A correlation rule was still generated."
        entries.append(entry)

    entries.sort(key=lambda e: (e.status != STATUS_GENERATED, e.technique_id))
    LOG.info("Pack for %s: %d technique(s), %d rule(s), %d chain(s)", profile.label, len(entries),
             sum(len(e.rules) for e in entries), sum(len(e.chains) for e in entries))
    return DetectionPack(
        profile=profile,
        entries=entries,
        attack_version=dataset.version,
        sigmahq_release=sigmahq.release if sigmahq else None,
        with_campaigns=with_campaigns,
        gaps_only=gaps_only,
        chains_requested=chains,
        skeletons_included=include_skeletons,
    )


def render_pack_files(pack: DetectionPack, dataset: AttackDataset, bundle_options: BundleOptions,
                      include_banner: bool = True, include_stix: bool = True) -> tuple[dict[str, str], list[str]]:
    """Every file of a pack as ``{relative path: text}``, plus STIX validation errors.

    Shared by :func:`write_pack` (CLI) and the web UI's ZIP download, so both
    produce the same folder.
    """
    import json

    files: dict[str, str] = {}
    for entry in pack.entries:
        for rule in list(entry.rules) + list(entry.chains):
            files[f"sigma/{rule.filename()}"] = rule.to_yaml(include_banner=include_banner)

    bundle_errors: list[str] = []
    if include_stix and pack.generated:
        bundle = build_pack_bundle(
            pack.profile,
            [(entry.technique, entry.rules, entry.chains) for entry in pack.generated],
            dataset,
            bundle_options,
        )
        bundle_errors = validate_bundle(bundle)
        files[f"{pack.slug}_bundle.json"] = dump_bundle(bundle)

    files["README.md"] = pack.to_markdown()
    files["pack.json"] = json.dumps(pack.to_dict(), indent=2, ensure_ascii=False)
    return files, bundle_errors


def write_pack(pack: DetectionPack, output_root: Path, dataset: AttackDataset,
               bundle_options: BundleOptions, include_banner: bool = True,
               write_stix: bool = True) -> dict[str, Any]:
    """Write a pack folder; returns the paths written and any bundle errors."""
    folder = Path(output_root) / "packs" / pack.slug
    files, bundle_errors = render_pack_files(pack, dataset, bundle_options, include_banner, write_stix)
    written: dict[str, Any] = {"folder": folder, "rules": [], "bundle": None, "bundle_errors": bundle_errors}
    for relative, text in files.items():
        path = write_text(folder / relative, text)
        if relative.startswith("sigma/"):
            written["rules"].append(path)
        elif relative.endswith("_bundle.json"):
            written["bundle"] = path
        elif relative == "README.md":
            written["readme"] = path
        elif relative == "pack.json":
            written["json"] = path
    return written
