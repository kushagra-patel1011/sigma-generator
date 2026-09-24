"""Command line entry point.

    python -m src.main generate T1059.001            # one technique
    python -m src.main generate T1003.001 --chains   # + attack-chain correlation rule
    python -m src.main generate --group APT29        # detection pack for a threat group
    python -m src.main gaps T1621                    # what SigmaHQ already covers
    python -m src.main quality --group APT29         # how much real detection content ATT&CK supports
    python -m src.main info T1003.001
    python -m src.main search "run key"
    python -m src.main update
    python -m src.main validate output/
    python -m src.main ui                            # local web interface

Installed via ``pip install -e .`` the same commands are available as
``sigma-gen generate T1059.001``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

from . import __version__
from .attack_fetcher import DEFAULT_INDEX_URL, AttackDataset, download_bundle
from .mappings import resolve_telemetry
from .packs import write_pack
from .service import GenerateOptions, TechniqueResult, Workspace, technique_as_dict
from .sigma_generator import TIER_MEANING, TIER_ORDER, VALID_LEVEL, VALID_STATUS, validate_sigma_text, validate_with_pysigma
from .sigmahq import assess_coverage, default_index_path, download_index
from .stix_builder import VALID_TLP, dump_bundle, merge_bundles, validate_bundle
from .utils import (
    DEFAULT_OUTPUT_DIR,
    LOG,
    PROJECT_ROOT,
    SigmaGeneratorError,
    env_int,
    env_str,
    first_sentences,
    load_env,
    setup_logging,
    utcnow_iso,
    write_text,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_VALIDATION = 3


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigma-gen",
        description=(
            "Turn MITRE ATT&CK techniques, threat groups and software into draft Sigma rules, "
            "attack-chain correlation rules and STIX 2.1 bundles."
        ),
        epilog="Generated rules are drafts: review them before deploying to a SIEM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"sigma-generator {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="count", default=0,
                        help="-v for progress, -vv for debug output")
    common.add_argument("-q", "--quiet", action="store_true", help="only report errors")
    common.add_argument("--data", metavar="PATH", help="ATT&CK bundle to use (default: data/enterprise-attack.json)")
    common.add_argument("--sigmahq", metavar="PATH",
                        help="SigmaHQ index to use (default: data/sigmahq-index.json)")
    common.add_argument("--offline", action="store_true",
                        help="never touch the network; fail if data is not cached")

    threat = argparse.ArgumentParser(add_help=False)
    selector = threat.add_mutually_exclusive_group()
    selector.add_argument("--group", metavar="NAME", help="ATT&CK group by ID, name or alias (e.g. APT29, G0016)")
    selector.add_argument("--software", metavar="NAME", help="ATT&CK software by ID, name or alias (e.g. Mimikatz)")
    selector.add_argument("--campaign", metavar="NAME", help="ATT&CK campaign by ID or name (e.g. C0024)")
    threat.add_argument("--with-campaigns", action="store_true",
                        help="for a group, also include techniques from campaigns attributed to it")
    threat.add_argument("--from-file", metavar="PATH",
                        help="read technique IDs from a file (one per line, # comments allowed)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # -- generate ---------------------------------------------------------- #
    generate = subparsers.add_parser(
        "generate", parents=[common, threat],
        help="generate rules for techniques, or a detection pack for a group/software/campaign",
        description="Generate draft Sigma rules and STIX bundles.",
    )
    generate.add_argument("techniques", nargs="*", metavar="TECHNIQUE",
                          help="ATT&CK technique IDs, e.g. T1059.001 T1547.001")
    generate.add_argument("--chains", action="store_true",
                          help="also build correlation rules: attack chains from multi-step ATT&CK analytics, "
                               "and count thresholds where ATT&CK describes volume")
    generate.add_argument("--include-skeletons", action="store_true",
                          help="write skeleton rules (status: unsupported) for techniques ATT&CK gives no "
                               "concrete values for, instead of skipping them")
    generate.add_argument("--gaps-only", action="store_true",
                          help="only generate for telemetry SigmaHQ has no rule for")
    generate.add_argument("--platform", help="restrict to one ATT&CK platform, e.g. Windows, Linux, IaaS")
    generate.add_argument("--analytic", metavar="AN####",
                          help="use one specific ATT&CK analytic instead of the best-ranked one")
    generate.add_argument("--all-analytics", action="store_true",
                          help="emit one rule per ATT&CK analytic instead of only the best one")
    generate.add_argument("--max-rules", type=int, default=0, metavar="N",
                          help="cap the rules per technique when --all-analytics is used")
    generate.add_argument("-o", "--output-dir", default=None,
                          help="output root (default: output/, override with SIGMA_OUTPUT_DIR)")
    generate.add_argument("--stdout", action="store_true", help="print rules instead of writing files")
    generate.add_argument("--no-sigma", action="store_true", help="skip writing the Sigma rule files")
    generate.add_argument("--no-stix", action="store_true", help="skip writing the STIX bundle")
    generate.add_argument("--merge-stix", action="store_true",
                          help="write one merged STIX bundle instead of one per technique")
    generate.add_argument("--no-banner", action="store_true",
                          help="omit the provenance comment banner from the rule files")
    generate.add_argument("--author", help="value for the rule's author field")
    generate.add_argument("--status", choices=VALID_STATUS, help="value for the rule's status field")
    generate.add_argument("--level", choices=VALID_LEVEL, help="force the rule level instead of deriving it")
    generate.add_argument("--tlp", choices=VALID_TLP, help="TLP marking for the STIX bundle (default: amber)")
    generate.add_argument("--template", metavar="PATH", help="alternative Sigma template file")
    generate.add_argument("--keep-revoked", action="store_true",
                          help="generate for a revoked technique ID instead of the ID that replaced it")
    generate.add_argument("--deterministic", action="store_true",
                          help="derive UUIDs from the technique so repeated runs are byte-identical")
    generate.add_argument("--strict", action="store_true",
                          help="fail if a generated rule does not validate (also uses pySigma when installed)")
    generate.set_defaults(func=cmd_generate)

    # -- gaps -------------------------------------------------------------- #
    gaps = subparsers.add_parser(
        "gaps", parents=[common, threat],
        help="compare ATT&CK's recommended telemetry with existing SigmaHQ rules",
        description="Show which log sources ATT&CK recommends that SigmaHQ already has rules for.",
    )
    gaps.add_argument("techniques", nargs="*", metavar="TECHNIQUE")
    gaps.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    gaps.set_defaults(func=cmd_gaps)

    # -- quality ----------------------------------------------------------- #
    quality = subparsers.add_parser(
        "quality", parents=[common, threat],
        help="report the quality tier of the rule each technique would get",
        description=(
            "Grade the best rule for each technique: strong (two or more independent signals), moderate "
            "(one signal), weak (broad hunting rule) or no rule (ATT&CK gives no concrete values). "
            "With no technique IDs or threat selector, every active ATT&CK technique is graded."
        ),
    )
    quality.add_argument("techniques", nargs="*", metavar="TECHNIQUE")
    quality.add_argument("--platform", help="restrict to one ATT&CK platform")
    quality.add_argument("--details", action="store_true", help="list every technique, not just the totals")
    quality.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    quality.set_defaults(func=cmd_quality)

    # -- info -------------------------------------------------------------- #
    info = subparsers.add_parser("info", parents=[common],
                                 help="show what ATT&CK knows about a technique, group, software or campaign")
    info.add_argument("identifier", metavar="ID", help="T1003.001, G0016, S0002 or C0024")
    info.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    info.set_defaults(func=cmd_info)

    # -- search ------------------------------------------------------------ #
    search = subparsers.add_parser("search", parents=[common],
                                   help="find techniques (or groups/software/campaigns) by ID, name or text")
    search.add_argument("query", nargs="+", metavar="QUERY")
    kinds = search.add_mutually_exclusive_group()
    kinds.add_argument("--groups", dest="kind", action="store_const", const="group", help="search threat groups")
    kinds.add_argument("--software", dest="kind", action="store_const", const="software", help="search software")
    kinds.add_argument("--campaigns", dest="kind", action="store_const", const="campaign", help="search campaigns")
    search.add_argument("-n", "--limit", type=int, default=20, help="maximum results (default: 20)")
    search.set_defaults(func=cmd_search, kind=None)

    # -- update ------------------------------------------------------------ #
    update = subparsers.add_parser("update", parents=[common],
                                   help="download or refresh the ATT&CK bundle and SigmaHQ index")
    only = update.add_mutually_exclusive_group()
    only.add_argument("--attack-only", action="store_true", help="refresh only the ATT&CK bundle")
    only.add_argument("--sigmahq-only", action="store_true", help="refresh only the SigmaHQ index")
    update.add_argument("--url", help="download a specific ATT&CK bundle URL instead of the newest release")
    update.add_argument("--index-url", default=None, help="ATT&CK collection index URL")
    update.add_argument("--force", action="store_true", help="kept for compatibility; update always refreshes")
    update.set_defaults(func=cmd_update)

    # -- validate ---------------------------------------------------------- #
    validate = subparsers.add_parser("validate", parents=[common],
                                     help="validate Sigma rules, correlation rules and STIX bundles")
    validate.add_argument("paths", nargs="+", metavar="PATH",
                          help="files or directories (.yml -> Sigma, .json -> STIX)")
    validate.set_defaults(func=cmd_validate)

    # -- ui ------------------------------------------------------------------ #
    ui = subparsers.add_parser("ui", parents=[common], help="start the local web interface")
    ui.add_argument("--host", default="127.0.0.1",
                    help="interface to bind (default: 127.0.0.1, this computer only)")
    ui.add_argument("--port", type=int, default=8765, help="port to listen on (default: 8765)")
    ui.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    ui.set_defaults(func=cmd_ui)

    return parser


# --------------------------------------------------------------------------- #
# Helpers shared by commands
# --------------------------------------------------------------------------- #
def _workspace(args: argparse.Namespace) -> Workspace:
    return Workspace(data_path=args.data, sigmahq_path=getattr(args, "sigmahq", None), offline=args.offline)


def _threat_selector(args: argparse.Namespace) -> tuple[Optional[str], Optional[str]]:
    for kind in ("group", "software", "campaign"):
        value = getattr(args, kind, None)
        if value:
            return value, kind
    return None, None


def _technique_ids(args: argparse.Namespace) -> list[str]:
    ids = list(getattr(args, "techniques", []) or [])
    if getattr(args, "from_file", None):
        ids.extend(_read_id_file(args.from_file))
    unique: list[str] = []
    for raw in ids:
        value = raw.strip().upper()
        if value and value not in unique:
            unique.append(value)
    return unique


def _options(args: argparse.Namespace) -> GenerateOptions:
    return GenerateOptions(
        platform=args.platform,
        analytic=args.analytic,
        all_analytics=args.all_analytics,
        max_rules=args.max_rules,
        chains=args.chains,
        gaps_only=args.gaps_only,
        with_campaigns=args.with_campaigns,
        author=args.author,
        status=args.status,
        level=args.level,
        tlp=args.tlp,
        template=args.template,
        deterministic=args.deterministic,
        keep_revoked=args.keep_revoked,
        strict=args.strict,
        include_skeletons=args.include_skeletons,
    )


def _output_root(args: argparse.Namespace) -> Path:
    root = Path(args.output_dir or env_str("SIGMA_OUTPUT_DIR", str(DEFAULT_OUTPUT_DIR)))
    return root if root.is_absolute() else PROJECT_ROOT / root


# --------------------------------------------------------------------------- #
# generate
# --------------------------------------------------------------------------- #
def cmd_generate(args: argparse.Namespace) -> int:
    query, kind = _threat_selector(args)
    technique_ids = _technique_ids(args)
    if query and technique_ids:
        LOG.error("Pass either technique IDs or --group/--software/--campaign, not both.")
        return EXIT_ERROR
    if not query and not technique_ids:
        LOG.error("Nothing to generate. Pass technique IDs, --from-file, or --group/--software/--campaign.")
        return EXIT_ERROR
    if query:
        return _generate_pack(args, query, kind)
    return _generate_techniques(args, technique_ids)


def _generate_techniques(args: argparse.Namespace, technique_ids: list[str]) -> int:
    workspace = _workspace(args)
    options = _options(args)
    generator = workspace.generator(options)
    output_root = _output_root(args)
    sigma_dir, stix_dir = output_root / "sigma", output_root / "stix"

    written_rules: list[Path] = []
    written_chains: list[Path] = []
    written_bundles: list[Path] = []
    bundles: list[dict[str, Any]] = []
    failures: list[tuple[str, str]] = []
    covered: list[tuple[str, str]] = []
    insufficient: list[tuple[str, str]] = []
    tiers: dict[str, int] = {}
    validation_failures = 0
    done: set[str] = set()
    banner = not args.no_banner

    for technique_id in technique_ids:
        result = workspace.generate_technique(technique_id, options, generator, with_bundle=not args.no_stix)
        for warning in result.warnings:
            LOG.warning("%s", warning)
        if result.technique and result.technique.id in done:
            continue
        if result.technique:
            done.add(result.technique.id)

        if result.status in ("covered", "insufficient"):
            bucket = covered if result.status == "covered" else insufficient
            bucket.append((result.technique.id if result.technique else technique_id, result.reason))
            if not result.chains:
                continue
        elif not result.ok:
            failures.append((technique_id, result.reason or "no rule could be generated"))
            continue

        for filename, problems in result.problems.items():
            validation_failures += 1
            for problem in problems:
                LOG.error("%s: %s", filename, problem)

        for rule in list(result.rules) + list(result.chains):
            tiers[rule.quality.tier] = tiers.get(rule.quality.tier, 0) + 1
            text = rule.to_yaml(include_banner=banner)
            if args.stdout:
                print(text)
                print()
            elif not args.no_sigma:
                path = write_text(sigma_dir / rule.filename(), text)
                (written_chains if rule in result.chains else written_rules).append(path)
                LOG.info("Wrote %s", path)

        if result.bundle is not None:
            if args.merge_stix:
                bundles.append(result.bundle)
            elif args.stdout:
                print(dump_bundle(result.bundle))
            else:
                name = f"{result.technique.id.lower().replace('.', '_')}.json"
                written_bundles.append(write_text(stix_dir / name, dump_bundle(result.bundle)))

    if bundles:
        merged = merge_bundles(bundles, deterministic=args.deterministic)
        if args.stdout:
            print(dump_bundle(merged))
        else:
            name = f"bundle_{utcnow_iso().replace(':', '').replace('-', '').replace('.', '_')}.json"
            written_bundles.append(write_text(stix_dir / name, dump_bundle(merged)))

    if not args.quiet:
        _print_summary(written_rules, written_chains, written_bundles, failures, covered, validation_failures,
                       insufficient, tiers)

    if failures and not (written_rules or written_chains or written_bundles or covered or insufficient):
        return EXIT_ERROR
    if insufficient and not (written_rules or written_chains or written_bundles or covered):
        return EXIT_ERROR
    if validation_failures and args.strict:
        return EXIT_VALIDATION
    return EXIT_OK if not failures else EXIT_ERROR


def _generate_pack(args: argparse.Namespace, query: str, kind: Optional[str]) -> int:
    if args.stdout:
        LOG.error("--stdout is not supported for detection packs; they are written as a folder.")
        return EXIT_ERROR
    if args.analytic or args.all_analytics:
        LOG.warning("--analytic/--all-analytics are ignored for detection packs")

    workspace = _workspace(args)
    options = _options(args)
    generator = workspace.generator(options)
    pack = workspace.build_pack(query, kind, options, generator)

    validation_failures = 0
    for entry in pack.entries:
        for rule in list(entry.rules) + list(entry.chains):
            problems = validate_sigma_text(rule.to_yaml(include_banner=False))
            if args.strict:
                problems += validate_with_pysigma(rule.to_yaml(include_banner=False))[1]
            for problem in problems:
                LOG.error("%s: %s", rule.filename(), problem)
            validation_failures += bool(problems)

    written = write_pack(pack, _output_root(args), workspace.dataset,
                         workspace.bundle_options(options, generator),
                         include_banner=not args.no_banner, write_stix=not args.no_stix)
    for problem in written["bundle_errors"]:
        LOG.error("STIX bundle: %s", problem)
    validation_failures += bool(written["bundle_errors"])

    if not args.quiet:
        summary = pack.to_dict()["summary"]
        print()
        print(f"Detection pack for {pack.profile.label}: {summary['techniques']} technique(s) attributed by ATT&CK")
        print(f"  {summary['rules']} Sigma rule(s), {summary['correlation_rules']} correlation rule(s) "
              f"for {summary['techniques_with_rules']} technique(s)")
        quality = summary["quality"]
        print("  Quality: " + ", ".join(f"{quality[tier]} {tier}" for tier in ("strong", "moderate", "weak", "placeholder")
                                        if quality[tier] or tier != "placeholder"))
        if pack.sigmahq_release:
            no_rules = sum(1 for e in pack.entries if e.coverage and e.coverage.usable_sources
                           and not e.coverage.exact_rules)
            print(f"  SigmaHQ {pack.sigmahq_release}: no existing rule for {no_rules} of these techniques"
                  + (f", {summary['covered_by_sigmahq']} fully covered and skipped" if pack.gaps_only else ""))
        if summary["insufficient_evidence"]:
            print(f"  {summary['insufficient_evidence']} technique(s) skipped: ATT&CK gives no concrete values "
                  "(--include-skeletons writes skeletons)")
        if summary["unmappable"]:
            print(f"  {summary['unmappable']} technique(s) could not be expressed as Sigma")
        print(f"  Folder: {_relative(written['folder'])}")
        print(f"  Summary: {_relative(written['readme'])}")
        if written["bundle"]:
            print(f"  STIX bundle: {_relative(written['bundle'])}")
        if validation_failures:
            print(f"\n{validation_failures} generated artefact(s) failed validation - see the errors above.")

    if not pack.generated:
        return EXIT_ERROR
    if validation_failures and args.strict:
        return EXIT_VALIDATION
    return EXIT_OK


# --------------------------------------------------------------------------- #
# gaps
# --------------------------------------------------------------------------- #
def cmd_gaps(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    query, kind = _threat_selector(args)
    technique_ids = _technique_ids(args)
    if query and technique_ids:
        LOG.error("Pass either technique IDs or --group/--software/--campaign, not both.")
        return EXIT_ERROR
    if query:
        profile = workspace.resolve_threat(query, kind, with_campaigns=args.with_campaigns)
        technique_ids = list(profile.technique_ids)
        heading = f"{profile.label}: {len(technique_ids)} technique(s) attributed by ATT&CK"
    elif technique_ids:
        heading = ""
    else:
        LOG.error("Pass technique IDs or --group/--software/--campaign.")
        return EXIT_ERROR

    index = workspace.sigmahq(required=True)
    reports = []
    missing: list[str] = []
    for technique_id in technique_ids:
        try:
            technique = workspace.dataset.get_technique(technique_id)
        except SigmaGeneratorError as exc:
            missing.append(f"{technique_id}: {exc}")
            continue
        reports.append(assess_coverage(technique, index))

    if args.json:
        print(json.dumps({"sigmahq_release": index.release, "techniques": [r.to_dict() for r in reports],
                          "errors": missing}, indent=2, ensure_ascii=False))
        return EXIT_OK if reports else EXIT_ERROR

    print(f"SigmaHQ {index.release} - {len(index.rules)} ATT&CK-tagged rules")
    if heading:
        print(heading)
    detailed = len(reports) <= 3
    if not detailed:
        print()
        print(f"{'Technique':<11} {'Name':<44} {'SigmaHQ':>8} {'Telemetry covered':>18}  Status")
    for report in reports:
        usable = report.usable_sources
        ratio = f"{len(report.covered_sources)}/{len(usable)}" if usable else "-"
        if not detailed:
            print(f"{report.technique_id:<11} {report.technique_name[:44]:<44} {len(report.exact_rules):>8} "
                  f"{ratio:>18}  {report.status}")
            continue
        print()
        print(f"{report.technique_id} {report.technique_name}")
        print(f"  SigmaHQ rules tagged {report.technique_id}: {len(report.exact_rules)}"
              f" (+{len(report.related_rules)} on the parent/sub-techniques)")
        print(f"  ATT&CK-recommended telemetry covered: {ratio}  -> {report.status}")
        for source in report.sources:
            if not source.usable:
                verdict = "not expressible as Sigma"
            elif source.covered:
                verdict = f"covered by {len(source.rules)} rule(s)"
            else:
                verdict = "GAP"
            print(f"    {source.analytic_id:<7} {source.log_source.describe()[:46]:<46} "
                  f"-> {source.mapping.logsource.describe()[:28]:<28} {verdict}")
        if report.gaps:
            print(f"  Fill the gaps:  python -m src.main generate {report.technique_id} --gaps-only")

    if not detailed:
        no_rules = sum(1 for r in reports if r.status == "no-rules")
        with_gaps = sum(1 for r in reports if r.gaps)
        print()
        print(f"{no_rules} technique(s) have no SigmaHQ rule; {with_gaps} have at least one uncovered log source.")
    for problem in missing:
        LOG.error("%s", problem)
    return EXIT_OK if reports else EXIT_ERROR


# --------------------------------------------------------------------------- #
# quality
# --------------------------------------------------------------------------- #
def cmd_quality(args: argparse.Namespace) -> int:
    from .packs import context_for
    from .utils import FullyCoveredError, InsufficientEvidenceError, UnmappableTechniqueError

    workspace = _workspace(args)
    dataset = workspace.dataset
    query, kind = _threat_selector(args)
    technique_ids = _technique_ids(args)
    if query and technique_ids:
        LOG.error("Pass either technique IDs or --group/--software/--campaign, not both.")
        return EXIT_ERROR
    scope = "every active ATT&CK technique"
    profile = None
    if query:
        profile = workspace.resolve_threat(query, kind, with_campaigns=args.with_campaigns)
        technique_ids = list(profile.technique_ids)
        scope = f"techniques attributed to {profile.label}"
    elif technique_ids:
        scope = f"{len(technique_ids)} technique(s)"
    else:
        technique_ids = [tid for tid in dataset.technique_ids()
                         if not (dataset.get_technique(tid).revoked or dataset.get_technique(tid).deprecated)]

    generator = workspace.generator(GenerateOptions())
    rows: list[dict[str, Any]] = []
    for technique_id in technique_ids:
        try:
            technique = dataset.get_technique(technique_id)
        except SigmaGeneratorError as exc:
            rows.append({"id": technique_id, "name": "", "grade": "error", "detail": str(exc)})
            continue
        row: dict[str, Any] = {"id": technique.id, "name": technique.name}
        # Grade what a pack would contain: the actor's own procedures are mined first.
        context = context_for(profile, technique.id) if profile else None
        try:
            rule = generator.generate(technique, platform=args.platform, context=context)[0]
            row.update(grade=rule.quality.tier, detail="; ".join(rule.quality.reasons),
                       logsource=rule.provenance.logsource_label, level=rule.level)
        except InsufficientEvidenceError:
            row.update(grade="no values", detail="ATT&CK names telemetry but no concrete values")
        except (UnmappableTechniqueError, FullyCoveredError):
            row.update(grade="unmappable", detail="telemetry lives outside the log pipeline")
        correlations = generator.generate_correlations(technique, platform=args.platform, context=context)
        row["correlations"] = [{"kind": c.kind, "type": c.correlation["type"], "grade": c.quality.tier}
                               for c in correlations]
        rows.append(row)

    grades = ["strong", "moderate", "weak", "no values", "unmappable", "error"]
    totals = {grade: sum(1 for row in rows if row["grade"] == grade) for grade in grades}
    correlation_totals: dict[str, int] = {}
    for row in rows:
        for correlation in row.get("correlations", []):
            correlation_totals[correlation["type"]] = correlation_totals.get(correlation["type"], 0) + 1

    if args.json:
        print(json.dumps({"scope": scope, "attack_version": dataset.version, "totals": totals,
                          "correlations": correlation_totals, "techniques": rows}, indent=2, ensure_ascii=False))
        return EXIT_OK

    total = len(rows) or 1
    print(f"Rule quality for {scope} (ATT&CK v{dataset.version})")
    print()
    meanings = {**TIER_MEANING, "no values": "ATT&CK names telemetry but no concrete values - no rule written",
                "unmappable": "telemetry lives outside a defender's logs", "error": "technique not found"}
    for grade in grades:
        if totals[grade] or grade in ("strong", "moderate", "weak"):
            print(f"  {grade:<11} {totals[grade]:>5}  {100 * totals[grade] / total:5.1f}%   {meanings[grade]}")
    deployable = totals["strong"] + totals["moderate"]
    print(f"\n  Deployable (strong + moderate): {deployable} of {len(rows)} ({100 * deployable / total:.1f}%)")
    if correlation_totals:
        print("  Correlation rules available: " + ", ".join(f"{count} {name}" for name, count in sorted(correlation_totals.items())))

    if args.details or len(rows) <= 25:
        print()
        print(f"{'Technique':<11} {'Grade':<11} {'Log source':<30} Correlations / detail")
        for row in rows:
            extras = ", ".join(f"{c['type']} ({c['grade']})" for c in row.get("correlations", []))
            detail = extras or row.get("detail", "")
            print(f"{row['id']:<11} {row['grade']:<11} {row.get('logsource', '-')[:30]:<30} {detail[:70]}")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# info / search
# --------------------------------------------------------------------------- #
def cmd_info(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    identifier = args.identifier.strip()
    if workspace.is_threat_id(identifier):
        return _info_threat(workspace, identifier, args.json)

    technique = workspace.dataset.get_technique(identifier)
    dataset = workspace.dataset
    if args.json:
        print(json.dumps(technique_as_dict(technique, dataset.version), indent=2, ensure_ascii=False))
        return EXIT_OK

    print(f"{technique.id}  {technique.name}")
    print("=" * (len(technique.id) + len(technique.name) + 2))
    if technique.is_subtechnique and technique.parent_id:
        print(f"Sub-technique of : {technique.parent_id} {technique.parent_name}")
    print(f"Tactics          : {', '.join(technique.tactics) or '-'}")
    print(f"Platforms        : {', '.join(technique.platforms) or '-'}")
    print(f"ATT&CK version   : {technique.version} (bundle {dataset.version})")
    print(f"Last modified    : {technique.modified[:10]}")
    if technique.revoked:
        print(f"Status           : REVOKED{' -> ' + technique.revoked_by if technique.revoked_by else ''}")
    elif technique.deprecated:
        print("Status           : DEPRECATED")
    print(f"URL              : {technique.url}")
    if technique.mitigations:
        print(f"Mitigations      : {', '.join(technique.mitigations[:6])}")
    print()
    summary = technique.description.split("\n")[0]
    print(summary[:600] + ("..." if len(summary) > 600 else ""))

    if not technique.detection_strategies:
        print()
        print("ATT&CK ships no detection strategy for this technique; generation will fall back to "
              "platform-level telemetry.")
        return EXIT_OK

    for strategy in technique.detection_strategies:
        print()
        print(f"[{strategy.id}] {strategy.name}")
        for analytic in strategy.analytics:
            platforms = ", ".join(analytic.platforms) or "any platform"
            print(f"  {analytic.id} ({platforms})")
            print(f"    {analytic.description[:220]}")
            for log_source in analytic.log_sources:
                platform = analytic.platforms[0] if analytic.platforms else None
                mapping = resolve_telemetry(
                    log_source.name, log_source.channel, log_source.data_component, platform
                )
                target = mapping.logsource.describe() if mapping.is_usable else "NOT MAPPABLE"
                print(f"      - {log_source.describe():<58} -> {target}  [{mapping.confidence:.2f}]")
            if analytic.mutable_elements:
                knobs = ", ".join(name for name, _ in analytic.mutable_elements)
                print(f"      tuning knobs: {knobs}")
    return EXIT_OK


def _info_threat(workspace: Workspace, identifier: str, as_json: bool) -> int:
    profile = workspace.resolve_threat(identifier)
    if as_json:
        print(json.dumps(workspace.threat_dict(profile), indent=2, ensure_ascii=False))
        return EXIT_OK
    print(f"{profile.id}  {profile.name}  ({profile.kind})")
    print("=" * (len(profile.id) + len(profile.name) + len(profile.kind) + 6))
    if profile.aliases:
        print(f"Also known as : {', '.join(profile.aliases)}")
    if profile.campaigns:
        print(f"Campaigns     : {', '.join(profile.campaigns)}")
    print(f"URL           : {profile.url}")
    print()
    print(first_sentences(profile.description, 3, 700))
    print()
    print(f"Techniques used ({len(profile.technique_ids)}):")
    for technique_id in profile.technique_ids:
        procedures = profile.procedures_for(technique_id)
        print(f"  {technique_id:<10} {procedures[0].technique_name}")
        if procedures[0].description:
            print(f"             {first_sentences(procedures[0].description, 1, 150)}")
    print()
    print(f"Build a detection pack:  python -m src.main generate --{profile.kind} {profile.id} --chains")
    return EXIT_OK


def cmd_search(args: argparse.Namespace) -> int:
    workspace = _workspace(args)
    query = " ".join(args.query)
    if args.kind:
        profiles = workspace.dataset.search_threats(query, args.kind, limit=args.limit)
        if not profiles:
            print(f"No {args.kind} matches '{query}'.")
            return EXIT_ERROR
        for profile in profiles:
            aliases = ", ".join(profile.aliases[:4])
            print(f"{profile.id:<7} {profile.name[:34]:<34} {len(profile.technique_ids):>3} technique(s)  {aliases[:60]}")
        return EXIT_OK

    results = workspace.dataset.search(query, limit=args.limit)
    if not results:
        print(f"No technique matches '{query}'. (Looking for a group? Add --groups.)")
        return EXIT_ERROR
    for technique in results:
        print(f"{technique.id:<12} {technique.name[:52]:<52} "
              f"{', '.join(technique.tactics)[:34]:<34} {len(technique.analytics)} analytic(s)")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# update / validate / ui
# --------------------------------------------------------------------------- #
def cmd_update(args: argparse.Namespace) -> int:
    if args.offline:
        LOG.error("update needs network access; drop --offline")
        return EXIT_ERROR

    if not args.sigmahq_only:
        data_path = Path(args.data or env_str("ATTACK_DATA_PATH", "data/enterprise-attack.json"))
        if not data_path.is_absolute():
            data_path = PROJECT_ROOT / data_path
        if data_path.is_file():
            try:
                print(f"Cached ATT&CK version {AttackDataset.from_file(data_path).version}; checking for a newer release...")
            except SigmaGeneratorError:
                LOG.warning("Existing ATT&CK cache is unreadable; re-downloading")
        download_bundle(
            data_path,
            url=args.url,
            index_url=args.index_url or env_str("ATTACK_INDEX_URL", DEFAULT_INDEX_URL),
            timeout=env_int("ATTACK_HTTP_TIMEOUT", 60),
        )
        meta = AttackDataset.from_file(data_path).metadata()
        print(f"ATT&CK {meta['version']} ready: {meta['technique_count']} techniques, "
              f"{meta['detection_strategy_count']} detection strategies, {meta['analytic_count']} analytics")

    if not args.attack_only:
        index = download_index(default_index_path(args.sigmahq))
        print(f"SigmaHQ {index.release} ready: {len(index.rules)} ATT&CK-tagged rules "
              f"covering {index.technique_count} techniques")
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    paths = _expand_paths(args.paths)
    if not paths:
        LOG.error("No .yml or .json files found in the given paths")
        return EXIT_ERROR

    checked = failed = 0
    pysigma_used = False
    for path in paths:
        checked += 1
        try:
            if path.suffix.lower() in (".yml", ".yaml"):
                text = path.read_text(encoding="utf-8")
                problems = validate_sigma_text(text)
                ran, extra = validate_with_pysigma(text)
                pysigma_used = pysigma_used or ran
                problems.extend(extra)
            else:
                problems = validate_bundle(json.loads(path.read_text(encoding="utf-8")))
        except Exception as exc:
            problems = [f"could not parse: {exc}"]

        if problems:
            failed += 1
            print(f"FAIL {path}")
            for problem in problems:
                print(f"     - {problem}")
        else:
            print(f"OK   {path}")

    print()
    print(f"{checked - failed}/{checked} file(s) valid"
          + ("" if pysigma_used else "  (install pySigma for deeper Sigma checks)"))
    return EXIT_OK if not failed else EXIT_VALIDATION


def cmd_ui(args: argparse.Namespace) -> int:
    from .web.server import serve

    return serve(_workspace(args), host=args.host, port=args.port, open_browser=not args.no_browser)


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _read_id_file(path: str) -> list[str]:
    identifiers: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            identifiers.extend(part for part in line.replace(",", " ").split() if part)
    return identifiers


def _expand_paths(paths: Sequence[str]) -> list[Path]:
    found: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            found.extend(sorted(p for p in path.rglob("*")
                                if p.suffix.lower() in (".yml", ".yaml", ".json") and p.name != "pack.json"))
        elif path.is_file():
            found.append(path)
        else:
            LOG.warning("Skipping %s (not found)", path)
    return found


def _print_summary(rules: Sequence[Path], chains: Sequence[Path], bundles: Sequence[Path],
                   failures: Sequence[tuple[str, str]], covered: Sequence[tuple[str, str]],
                   validation_failures: int, insufficient: Sequence[tuple[str, str]] = (),
                   tiers: Optional[dict[str, int]] = None) -> None:
    if rules or chains or bundles:
        print()
        print(f"Wrote {len(rules)} Sigma rule(s), {len(chains)} correlation rule(s) "
              f"and {len(bundles)} STIX bundle(s).")
        listed = [("rule  ", p) for p in rules] + [("corr  ", p) for p in chains] + [("bundle", p) for p in bundles]
        for label, path in listed[:12]:
            print(f"  {label} {_relative(path)}")
        if len(listed) > 12:
            print(f"  ... and {len(listed) - 12} more")
        if tiers:
            print("Quality: " + ", ".join(f"{tiers[tier]} {tier}" for tier in reversed(TIER_ORDER) if tiers.get(tier)))
            if tiers.get("weak"):
                print("  weak = broad hunting rule, tagged detection.threat-hunting and capped at level low")
    if insufficient:
        print(f"\n{len(insufficient)} technique(s) skipped - ATT&CK gives no concrete values to detect on "
              "(--include-skeletons writes skeleton rules):")
        for technique_id, reason in insufficient:
            print(f"  {technique_id}: {reason.split(': ', 1)[-1].splitlines()[0][:160]}")
    if covered:
        print(f"\n{len(covered)} technique(s) already fully covered by SigmaHQ:")
        for technique_id, reason in covered:
            print(f"  {technique_id}: {reason.splitlines()[0]}")
    if validation_failures:
        print(f"\n{validation_failures} generated artefact(s) failed validation - see the errors above.")
    if failures:
        print(f"\n{len(failures)} technique(s) produced no rule:")
        for technique_id, reason in failures:
            print(f"  {technique_id}: {reason.splitlines()[0]}")


def _relative(path: Path) -> str:
    try:
        return str(Path(path).relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def _ensure_utf8_output() -> None:
    """ATT&CK text contains characters like '→' and '–'.  Windows falls back to
    cp1252 when output is redirected (``> rule.yml``), which would crash on them."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if encoding != "utf8" and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - exotic streams
                pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    _ensure_utf8_output()
    load_env()
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(getattr(args, "verbose", 0), getattr(args, "quiet", False))
    try:
        return args.func(args)
    except SigmaGeneratorError as exc:
        LOG.error("%s", exc)
        return EXIT_ERROR
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        LOG.error("Interrupted")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
