"""Turn an ATT&CK technique into draft Sigma rules.

The pipeline for one rule is:

    technique -> for every analytic, group its log sources by Sigma logsource
              -> mine evidence: the log source's own channel text first, then the
                 group's procedures, the analytic, its tuning knobs and the technique
              -> place each value in the field the telemetry records it in
              -> assess the rule's quality (strong / moderate / weak / placeholder)
              -> keep the best-supported candidate and render YAML with a banner

Quality is a first-class output, not a hidden score.  A rule that only matches an
event type is labelled *weak* and tagged for threat hunting; a technique ATT&CK
gives no concrete values for produces no rule at all unless a skeleton is asked
for.  Everything the tool inferred is written into the banner, because a generated
rule is a starting point for a detection engineer, never a drop-in production rule.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from . import __version__
from .attack_fetcher import Analytic, DetectionStrategy, Technique, pick_platform
from .mappings import (
    CONF_COMPONENT,
    LEVEL_ORDER,
    TACTIC_LEVEL,
    TelemetryMapping,
    downgrade_level,
    resolve_telemetry,
)
from .utils import (
    LOG,
    NIX_UTILITIES,
    WINDOWS_SYSTEM_FILES,
    WINDOWS_UTILITIES,
    Artefacts,
    FullyCoveredError,
    InsufficientEvidenceError,
    LiteralScalar,
    TEMPLATE_DIR,
    UnmappableTechniqueError,
    comment_block,
    dump_yaml,
    extract_artefacts,
    first_sentences,
    load_all_yaml,
    load_yaml,
    minimise_contains,
    normalise_registry_key,
    normalise_windows_path,
    slugify,
    split_sentences,
    today_iso,
    wrap_text,
)

#: UUIDv5 namespace used when --deterministic is requested.  Random (v4) IDs are
#: the default because the Sigma spec expects a fresh UUID per rule.
RULE_NAMESPACE = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")

VALID_STATUS = ("stable", "test", "experimental", "deprecated", "unsupported")
VALID_LEVEL = LEVEL_ORDER

_CONDITION_KEYWORDS = {"and", "or", "not", "of", "them", "all", "1", "any"}
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\*?")

#: Sigma logsource categories rendered as a readable phrase in rule titles.
_CATEGORY_LABELS = {
    "process_creation": "Process Creation",
    "process_access": "Process Access",
    "process_termination": "Process Termination",
    "process_tampering": "Process Tampering",
    "image_load": "Module Load",
    "driver_load": "Driver Load",
    "file_event": "File Creation",
    "file_change": "File Change",
    "file_delete": "File Deletion",
    "file_access": "File Access",
    "registry_add": "Registry Key Creation",
    "registry_set": "Registry Modification",
    "registry_delete": "Registry Key Deletion",
    "registry_rename": "Registry Key Rename",
    "registry_event": "Registry Activity",
    "network_connection": "Network Connection",
    "dns_query": "DNS Query",
    "pipe_created": "Named Pipe Creation",
    "create_remote_thread": "Remote Thread Creation",
    "create_stream_hash": "Alternate Data Stream Creation",
    "raw_access_thread": "Raw Disk Access",
    "wmi_event": "WMI Activity",
    "ps_script": "PowerShell Script Block Logging",
    "ps_module": "PowerShell Module Logging",
    "proxy": "Proxy Traffic",
    "firewall": "Firewall Activity",
    "application": "Application Log",
}

_SERVICE_LABELS = {
    "cloudtrail": "CloudTrail", "vpcflow": "VPC Flow Logs", "cloudwatch": "CloudWatch",
    "signinlogs": "Sign-In Logs", "auditlogs": "Audit Logs", "activitylogs": "Activity Logs",
    "gcp.audit": "Audit Logs", "google_workspace.admin": "Admin Audit", "audit": "Audit Logs",
    "powershell-classic": "PowerShell Classic", "codeintegrity-operational": "Code Integrity",
    "auditd": "Auditd", "syslog": "Syslog", "wmi": "WMI", "aaa": "AAA",
}

_PRODUCT_LABELS = {
    "aws": "AWS", "azure": "Azure", "gcp": "GCP", "m365": "Microsoft 365",
    "okta": "Okta", "github": "GitHub", "kubernetes": "Kubernetes",
    "google_workspace": "Google Workspace", "zeek": "Zeek", "esxi": "ESXi",
    "windows": "Windows", "linux": "Linux", "macos": "macOS", "cisco": "Cisco",
    "docker": "Docker",
}


# --------------------------------------------------------------------------- #
# Artefact placement
# --------------------------------------------------------------------------- #
#: Processes ATT&CK prose names as the *victim* of access or injection.  They
#: belong in TargetImage, never in Image/SourceImage.
TARGET_PROCESSES = frozenset({
    "lsass.exe", "lsaiso.exe", "csrss.exe", "winlogon.exe", "wininit.exe", "services.exe",
    "smss.exe", "explorer.exe", "svchost.exe", "spoolsv.exe",
})
HIGH_SIGNAL_TARGETS = frozenset({"lsass.exe", "lsaiso.exe"})
_PROCESS_EXTENSIONS = (".exe", ".com", ".scr")
_WINDOWS_LIBRARY_EXTENSIONS = (".dll", ".sys")
_NIX_LIBRARY_EXTENSIONS = (".so", ".dylib")
_SCRIPT_EXTENSIONS = (
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".bat", ".cmd", ".py", ".sh", ".jar",
)
#: Categories whose subject is an object (key, file, pipe) rather than a process.
OBJECT_FIRST_CATEGORIES = ("registry_", "file_", "create_stream_hash", "pipe_created", "raw_access_thread")
_MAX_VALUES = 12

#: Values so common in normal activity that on their own they detect nothing.
#: Compared after lower-casing and stripping leading path separators.
GENERIC_VALUES = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "explorer.exe", "svchost.exe", "rundll32.exe",
    "conhost.exe", "bash", "sh", "zsh", "python", "python3", "curl", "wget", "sudo", "ssh",
    ":\\windows", ":\\windows\\system32", ":\\windows\\syswow64", ":\\windows\\temp", ":\\programdata", "temp",
    ":\\users", "users", ":\\program files", ":\\program files (x86)",
    "appdata\\roaming", "appdata\\local", "users\\public", ":\\users\\public",
    "tmp", "var/tmp", "usr/bin", "bin", "etc", "library", "usr/local/bin", "dev/shm",
    "80", "443", "53",
})


def normalise_value(value: Any) -> str:
    """The comparison key for a selection value: lower-case, no leading separators."""
    return str(value).strip().lower().lstrip("\\/").rstrip("\\/")


def is_generic(value: Any) -> bool:
    """True for values normal activity is full of - including their full paths
    (``/bin/bash``, ``C:\\Windows\\System32\\cmd.exe``)."""
    key = normalise_value(value)
    if key in GENERIC_VALUES:
        return True
    separator = "/" if "/" in key else "\\"
    folder, found, name = key.rpartition(separator)
    return bool(found) and folder in GENERIC_VALUES and name in GENERIC_VALUES


def _is_specific_path(path: str) -> bool:
    """A path that narrows a command line, rather than naming a common root."""
    key = normalise_value(path)
    segments = [segment for segment in re.split(r"[\\/]+", key) if segment and segment != ":"]
    return key not in GENERIC_VALUES and len(segments) >= 2


@dataclass
class Placement:
    """Mined artefacts sorted by the part they play in one log source's events."""

    actors: list[str] = field(default_factory=list)        # processes doing something
    targets: list[str] = field(default_factory=list)       # processes acted upon
    libraries: list[str] = field(default_factory=list)     # DLLs, drivers, shared objects
    content: list[str] = field(default_factory=list)       # command-line / script fragments
    paths: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    access_masks: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    native_content: bool = False                           # content not spilled from other roles


def place_artefacts(artefacts: Artefacts, mapping: TelemetryMapping,
                    exclude: Iterable[str] = ()) -> Placement:
    """Decide which field each mined artefact belongs in for ``mapping``.

    * Binaries are only placed on host log sources, and only when they fit the
      OS: ``powershell.exe`` never lands in a Linux rule, ``base64`` never in a
      Windows one.
    * Victim processes (lsass.exe) go to TargetImage when the source has one,
      otherwise into the command line where tools name them
      (``procdump -ma lsass.exe``).
    * DLLs go to ImageLoaded when the source has one, otherwise into the command
      line (``rundll32 comsvcs.dll, MiniDump``).
    * Registry keys and paths are rewritten to match expanded telemetry.  A
      process event with no file field still carries *specific* paths in its
      command line (``kextload /Library/Extensions/x.kext``).
    * ``exclude`` removes values already used elsewhere - how attack-chain steps
      are kept from repeating each other.
    """
    product = (mapping.logsource.product or "").lower()
    roles = mapping.roles
    windows = product == "windows"
    nix = product in ("linux", "macos")
    separator = "\\" if windows else "/"
    placement = Placement()
    scripts: list[str] = []

    if windows or nix:
        library_extensions = _WINDOWS_LIBRARY_EXTENSIONS if windows else _NIX_LIBRARY_EXTENSIONS
        for name in artefacts.executables:
            lowered = name.lower()
            if windows and lowered.endswith(_PROCESS_EXTENSIONS):
                bucket = placement.targets if lowered in TARGET_PROCESSES else placement.actors
                bucket.append(separator + lowered)
            elif lowered.endswith(library_extensions):
                placement.libraries.append(separator + lowered)
            elif lowered.endswith(_SCRIPT_EXTENSIONS):
                scripts.append(lowered)
        native_tools = WINDOWS_UTILITIES if windows else NIX_UTILITIES
        for utility in artefacts.utilities:
            if utility in native_tools:
                placement.actors.append(separator + utility + (".exe" if windows else ""))

    content: list[str] = list(artefacts.flags)
    if windows:
        content += artefacts.cmdlets
    if windows or nix:
        content += scripts
    if "script" in roles:
        content += artefacts.api_calls
    placement.native_content = bool(content)

    if "target_image" not in roles:
        # Only credential stores are worth matching as text: `procdump -ma lsass.exe`
        # is a signal, a task or command line mentioning svchost.exe is not.
        content += [
            value.lstrip(separator) for value in placement.targets
            if value.lstrip(separator) in HIGH_SIGNAL_TARGETS
        ]
        placement.targets = []
    if "loaded_image" not in roles:
        content += [value.lstrip(separator) for value in placement.libraries]
        placement.libraries = []

    if windows:
        keys = [normalise_registry_key(key) for key in artefacts.registry_keys]
        if "registry_key" in roles:
            placement.registry_keys = minimise_contains(keys)[:_MAX_VALUES]
        elif roles.get("command_line"):
            content += keys  # `reg add HKCU\...\Run` puts the key in the command line
        paths = [normalise_windows_path(path) for path in artefacts.paths if "\\" in path]
    elif nix:
        paths = [path for path in artefacts.paths if path.startswith("/")]
    else:
        paths = []
    if "file" in roles:
        # `rundll32 C:\Windows\System32\comsvcs.dll, MiniDump` uses a Windows DLL;
        # a file event on that path would never fire during the attack.
        file_paths = [path for path in paths
                      if not (windows and re.split(r"[\\/]", path)[-1].lower() in WINDOWS_SYSTEM_FILES)]
        placement.paths = minimise_contains(file_paths)[:_MAX_VALUES]
    elif roles.get("command_line") and (windows or nix):
        content += [path for path in paths if _is_specific_path(path)]

    placement.actors = sorted(dict.fromkeys(placement.actors))[:_MAX_VALUES]
    placement.targets = sorted(dict.fromkeys(placement.targets))[:_MAX_VALUES]
    placement.libraries = sorted(dict.fromkeys(placement.libraries))[:_MAX_VALUES]
    placement.content = minimise_contains(content)[:16]
    placement.access_masks = list(artefacts.access_masks) if "access_mask" in roles else []
    placement.ports = list(artefacts.ports)[:_MAX_VALUES] if "port" in roles else []

    excluded = {normalise_value(value) for value in exclude}
    if excluded:
        for name in ("actors", "targets", "libraries", "content", "paths", "registry_keys", "access_masks", "ports"):
            setattr(placement, name, [v for v in getattr(placement, name) if normalise_value(v) not in excluded])
    return placement


# --------------------------------------------------------------------------- #
# Quality
# --------------------------------------------------------------------------- #
TIER_ORDER = ("placeholder", "weak", "moderate", "strong")
TIER_MEANING = {
    "strong": "two or more independent behavioural signals",
    "moderate": "one behavioural signal - review for noise",
    "weak": "matches broad activity - suitable for threat hunting, not alerting",
    "placeholder": "no concrete values - a skeleton to complete by hand",
}
#: Selections that pin down *what* an event is about.  A single one of these is
#: already a meaningful rule (a Run-key write, an access to lsass.exe).
_SUBJECT_SELECTIONS = ("selection_registry", "selection_target", "selection_loaded", "selection_path", "selection_port")
_NON_BEHAVIOURAL = ("condition", "selection_source", "selection_todo")


def selection_values(block: Any) -> list[Any]:
    values: list[Any] = []
    if isinstance(block, dict):
        for value in block.values():
            values.extend(value if isinstance(value, list) else [value])
    elif isinstance(block, list):
        values.extend(block)
    return values


@dataclass(frozen=True)
class RuleQuality:
    """How much real detection content a rule has - reported, never hidden."""

    tier: str
    signals: int
    reasons: tuple[str, ...] = ()

    @property
    def rank(self) -> int:
        return TIER_ORDER.index(self.tier)

    @property
    def meaning(self) -> str:
        return TIER_MEANING[self.tier]

    @property
    def label(self) -> str:
        return f"{self.tier} - {self.meaning}"


def assess_quality(detection: dict[str, Any]) -> RuleQuality:
    """Grade a detection block by its behavioural content.

    * strong      - two or more selections with specific values
    * moderate    - one subject selection (key, target, path, port...) or one
                    selection with several specific values
    * weak        - only an event type, a single value, or only values that are
                    common in normal activity (``powershell.exe``, ``/tmp``)
    * placeholder - nothing concrete at all
    """
    if not detection or "selection_todo" in detection:
        return RuleQuality("placeholder", 0, ("ATT&CK gave no concrete values for this telemetry",))

    behavioural = {name: selection_values(block) for name, block in detection.items() if name not in _NON_BEHAVIOURAL}
    specific = {name: [v for v in values if not is_generic(v)] for name, values in behavioural.items()}
    specific = {name: values for name, values in specific.items() if values}

    if not behavioural:
        return RuleQuality("weak", 0, ("only the event type is selected - every such event matches",))
    if not specific:
        values = ", ".join(str(v) for vals in behavioural.values() for v in vals)[:80]
        return RuleQuality("weak", 0, (f"only values common in normal activity ({values})",))
    if len(specific) >= 2:
        return RuleQuality("strong", len(specific), (f"{len(specific)} independent behavioural selections",))
    name, values = next(iter(specific.items()))
    if name in _SUBJECT_SELECTIONS or len(values) >= 2:
        reason = "a subject selection" if name in _SUBJECT_SELECTIONS else f"{len(values)} specific values in one selection"
        return RuleQuality("moderate", 1, (reason,))
    return RuleQuality("weak", 1, (f"rests on a single value ({values[0]})",))


# --------------------------------------------------------------------------- #
# Result objects
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ThreatContext:
    """Actor, software or campaign context for rules built into a detection pack.

    ATT&CK records *how* each group used each technique ("APT29 has used encoded
    PowerShell scripts...").  Those procedure examples are the most concrete prose
    ATT&CK has, so they are mined first when a rule is built for a group.
    """

    label: str                              # "APT29 (G0016)"
    url: str = ""
    sigma_tag: Optional[str] = None         # attack.g0016 / attack.s0002 (none for campaigns)
    procedures: tuple[str, ...] = ()        # procedure texts for the technique at hand
    platforms: tuple[str, ...] = ()         # software's ATT&CK platforms; groups and campaigns have none

    def fits(self, analytic: Optional[Analytic], product: Optional[str] = None) -> bool:
        """Whether ``analytic`` - and the Sigma ``product`` its telemetry resolved
        to - watch a platform this software runs on.  The product matters too:
        ATT&CK occasionally files a Linux log source under a macOS analytic."""
        if not self.platforms:
            return True
        wanted = {platform.lower() for platform in self.platforms}
        if (product or "").lower() in ("windows", "linux", "macos") and product.lower() not in wanted:
            return False
        if analytic is None or not analytic.platforms:
            return True
        return any(platform.lower() in wanted for platform in analytic.platforms)


@dataclass
class RuleProvenance:
    """Where every part of a generated rule came from."""

    technique_id: str
    technique_name: str
    attack_version: str = ""
    platform: Optional[str] = None
    strategy_id: Optional[str] = None
    strategy_name: Optional[str] = None
    analytic_id: Optional[str] = None
    analytic_description: str = ""
    telemetry_source: str = ""
    logsource_label: str = ""
    confidence: float = 0.0
    artefact_counts: dict[str, int] = field(default_factory=dict)
    mutable_elements: tuple[tuple[str, str], ...] = ()
    notes: tuple[str, ...] = ()
    threat_label: Optional[str] = None
    procedure_count: int = 0
    quality: RuleQuality = field(default_factory=lambda: RuleQuality("placeholder", 0))

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 0.9:
            return "high (ATT&CK named the exact event)"
        if self.confidence >= 0.7:
            return "medium (ATT&CK named the log source, not the event)"
        if self.confidence >= CONF_COMPONENT:
            return "low (inferred from the ATT&CK data component)"
        return "very low (platform-level guess)"


@dataclass
class SigmaRule:
    """A rendered Sigma rule plus the provenance banner that precedes it."""

    title: str
    id: str
    status: str
    description: str
    references: list[str]
    author: str
    date: str
    tags: list[str]
    logsource: dict[str, str]
    detection: dict[str, Any]
    fields: list[str]
    falsepositives: list[str]
    level: str
    provenance: RuleProvenance
    banner: list[str] = field(default_factory=list)
    key_order: tuple[str, ...] = (
        "title", "id", "status", "description", "references", "author", "date",
        "tags", "logsource", "detection", "fields", "falsepositives", "level",
    )

    @property
    def quality(self) -> RuleQuality:
        return self.provenance.quality

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {}
        for key in self.key_order:
            value = getattr(self, key, None)
            if value in (None, "", [], {}):
                continue
            body[key] = LiteralScalar(value) if key == "description" and "\n" in value else value
        return body

    def to_yaml(self, include_banner: bool = True) -> str:
        rendered = dump_yaml(self.to_dict())
        if include_banner and self.banner:
            return comment_block(self.banner) + "\n" + rendered
        return rendered

    def filename(self) -> str:
        source = self.logsource.get("category") or self.logsource.get("service") or self.logsource.get("product") or "rule"
        technique = self.provenance.technique_id.lower().replace(".", "_")
        return f"{technique}_{slugify(source, 30)}_{slugify(self.provenance.technique_name, 40)}.yml"


@dataclass
class ChainStep:
    """One base rule inside a correlation file."""

    name: str
    title: str
    id: str
    logsource: dict[str, str]
    detection: dict[str, Any]
    telemetry_source: str
    logsource_label: str
    confidence: float
    group_field: str
    quality: RuleQuality = field(default_factory=lambda: RuleQuality("weak", 0))

    def to_dict(self) -> dict[str, Any]:
        # The correlation spec reserves metadata (status, level, date...) for
        # the outermost correlation rule, so base rules stay minimal.
        return {
            "title": self.title,
            "id": self.id,
            "name": self.name,
            "logsource": self.logsource,
            "detection": self.detection,
        }


@dataclass
class ChainRule:
    """A Sigma correlation rule plus the base rules it references, as one file.

    ``kind`` is ``chain`` for a temporal correlation of several behaviours, or
    ``count`` for an ``event_count`` / ``value_count`` threshold over one.
    """

    title: str
    id: str
    status: str
    description: str
    references: list[str]
    author: str
    date: str
    tags: list[str]
    correlation: dict[str, Any]
    falsepositives: list[str]
    level: str
    steps: list[ChainStep]
    provenance: RuleProvenance
    banner: list[str] = field(default_factory=list)
    kind: str = "chain"

    @property
    def quality(self) -> RuleQuality:
        return self.provenance.quality

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "title": self.title,
            "id": self.id,
            "status": self.status,
            "description": LiteralScalar(self.description) if "\n" in self.description else self.description,
            "references": self.references,
            "author": self.author,
            "date": self.date,
            "tags": self.tags,
            "correlation": self.correlation,
            "falsepositives": self.falsepositives,
            "level": self.level,
        }
        return {key: value for key, value in body.items() if value not in (None, "", [], {})}

    def to_yaml(self, include_banner: bool = True) -> str:
        documents = [dump_yaml(self.to_dict())] + [dump_yaml(step.to_dict()) for step in self.steps]
        rendered = "---\n".join(documents)
        if include_banner and self.banner:
            return comment_block(self.banner) + "\n" + rendered
        return rendered

    def filename(self) -> str:
        """``mr_`` prefix, lowercase, <= 70 characters - the spec's naming guidance."""
        technique = self.provenance.technique_id.lower().replace(".", "_")
        analytic = (self.provenance.analytic_id or "chain").lower()
        prefix = f"mr_{technique}_{analytic}_" + ("count_" if self.kind == "count" else "")
        slug = slugify(self.provenance.technique_name, 70 - len(prefix) - len(".yml"))
        return f"{prefix}{slug}.yml"


# --------------------------------------------------------------------------- #
# Template handling
# --------------------------------------------------------------------------- #
#: Used when the template is missing or unreadable.
BUILTIN_DEFAULTS: dict[str, Any] = {
    "status": "experimental",
    "author": "sigma-generator",
    "falsepositives": ["Unknown"],
}


def load_template(path: Optional[str | Path] = None) -> tuple[tuple[str, ...], dict[str, Any]]:
    """Read field order and defaults from the Sigma template.

    Only values the template states *concretely* count as defaults - a
    ``<placeholder>`` means "the generator fills this in".  That is what makes
    ``level`` in the shipped template a placeholder (so it stays derived from the
    ATT&CK tactic) while a user who writes ``level: critical`` pins every rule.
    """
    template_path = Path(path) if path else TEMPLATE_DIR / "sigma_template.yml"
    order = SigmaRule.key_order
    if not template_path.is_file():
        LOG.warning("Sigma template %s not found - using built-in defaults", template_path)
        return order, dict(BUILTIN_DEFAULTS)

    parsed = load_yaml(template_path.read_text(encoding="utf-8")) or {}
    if not isinstance(parsed, dict):
        LOG.warning("Sigma template %s is not a mapping - using built-in defaults", template_path)
        return order, dict(BUILTIN_DEFAULTS)

    defaults: dict[str, Any] = {}
    for key in ("status", "level", "author"):
        value = parsed.get(key)
        if isinstance(value, str) and not value.startswith("<"):
            defaults[key] = value
    false_positives = parsed.get("falsepositives")
    if isinstance(false_positives, list) and false_positives and not str(false_positives[0]).startswith("<"):
        defaults["falsepositives"] = [str(item) for item in false_positives]
    return tuple(parsed.keys()), defaults


# --------------------------------------------------------------------------- #
# Evidence sources
# --------------------------------------------------------------------------- #
@dataclass
class TelemetrySource:
    """One Sigma logsource an analytic names, possibly through several references.

    ATT&CK often lists the same log source more than once in one analytic
    (``AWS:CloudTrail`` for ``DescribeInstances``, again for ``ListBuckets``...).
    They are merged so the rule watches every operation, not just the first.
    """

    mapping: TelemetryMapping
    channels: list[str]
    position: int


def _merge_base_selections(selections: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, list[Any]] = {}
    for selection in selections:
        for key, value in selection.items():
            bucket = merged.setdefault(key, [])
            for item in value if isinstance(value, list) else [value]:
                if item not in bucket:
                    bucket.append(item)
    return {key: values[0] if len(values) == 1 else values for key, values in merged.items()}


@dataclass
class _Candidate:
    strategy: Optional[DetectionStrategy]
    analytic: Optional[Analytic]
    source: TelemetrySource
    artefacts: Artefacts
    platform: Optional[str]
    detection: dict[str, Any]
    notes: list[str]
    quality: RuleQuality
    score: float
    platform_match: bool = True

    @property
    def mapping(self) -> TelemetryMapping:
        return self.source.mapping

    @property
    def sort_key(self) -> tuple[int, float, int]:
        """Deployable rules (moderate or strong) compete on telemetry, not selection count.

        Counting selections alone would prefer ``reg.exe`` plus a Run key on the
        command line (two selections) over any process writing a Run key (one
        selection) - the narrower rule.  So weak and placeholder rules always lose,
        and among deployable ones confidence, ATT&CK ordering and field fit decide,
        with only a nudge for extra signals.
        """
        band = min(self.quality.rank, TIER_ORDER.index("moderate"))
        nudge = 0.3 if self.quality.tier == "strong" else 0.0
        return (band, self.score + nudge, 1 if self.platform_match else 0)


# --------------------------------------------------------------------------- #
# Generator
# --------------------------------------------------------------------------- #
class SigmaRuleGenerator:
    """Builds :class:`SigmaRule` and :class:`ChainRule` objects from techniques."""

    DEFAULT_EVENT_THRESHOLD = 10
    DEFAULT_DISTINCT_THRESHOLD = 5
    TODO_VALUE = "TODO-replace-with-an-observed-value"

    def __init__(
        self,
        author: Optional[str] = None,
        status: Optional[str] = None,
        level: Optional[str] = None,
        deterministic: bool = False,
        template_path: Optional[str | Path] = None,
        artefact_limit: int = 8,
        attack_version: str = "",
    ) -> None:
        self.key_order, self.defaults = load_template(template_path)
        # Precedence: explicit argument > concrete template value > built-in default.
        self.author = author or self.defaults.get("author") or BUILTIN_DEFAULTS["author"]
        self.status = status or self.defaults.get("status") or BUILTIN_DEFAULTS["status"]
        self.level_override = level or self.defaults.get("level")
        self.default_falsepositives = list(
            self.defaults.get("falsepositives") or BUILTIN_DEFAULTS["falsepositives"]
        )
        self.deterministic = deterministic
        self.artefact_limit = artefact_limit
        self.attack_version = attack_version
        # Rules, chains and count rules all re-derive the same evidence per
        # analytic; one generator is short-lived, so a plain dict is enough.
        self._cache: dict[tuple, Any] = {}

    # -- public API -------------------------------------------------------- #
    def generate(
        self,
        technique: Technique,
        platform: Optional[str] = None,
        analytic_id: Optional[str] = None,
        all_analytics: bool = False,
        max_rules: int = 0,
        context: Optional[ThreatContext] = None,
        skip_mapping: Optional[Callable[[TelemetryMapping], bool]] = None,
        include_skeletons: bool = False,
    ) -> list[SigmaRule]:
        """Generate one rule (default) or one rule per ATT&CK analytic.

        With no ``platform`` given the platform is an *outcome*, not an input:
        every analytic competes and the best-supported rule wins - first by
        quality tier, then by how precisely ATT&CK named the telemetry.

        ``context`` adds a group's procedure examples to the mined text.
        ``skip_mapping`` excludes telemetry (used by ``--gaps-only``).
        ``include_skeletons`` keeps placeholder rules, which are otherwise
        refused with :class:`InsufficientEvidenceError`.
        """
        chosen_platform = self._requested_platform(technique, platform)
        candidates = self._candidates(technique, chosen_platform, analytic_id, context, skip_mapping)
        if not candidates:
            if skip_mapping and self._candidates(technique, chosen_platform, analytic_id, context, None):
                raise FullyCoveredError(
                    f"{technique.id} ({technique.name}): SigmaHQ already has rules for every log "
                    "source ATT&CK recommends - no gap to fill."
                )
            raise UnmappableTechniqueError(
                f"{technique.id} ({technique.name}) offers no telemetry this tool can express as a "
                "Sigma logsource. ATT&CK points at data that lives outside the defender's log "
                "pipeline (for example Internet scans or malware repositories)."
            )

        usable = candidates if include_skeletons else [c for c in candidates if c.quality.tier != "placeholder"]
        if not usable:
            raise InsufficientEvidenceError(self._insufficient_message(technique, candidates))

        if not all_analytics:
            usable = usable[:1]
        elif max_rules:
            usable = usable[:max_rules]

        rules = [self._build_rule(technique, candidate, context) for candidate in usable]
        LOG.info("Generated %d rule(s) for %s", len(rules), technique.id)
        return rules

    def generate_correlations(
        self,
        technique: Technique,
        platform: Optional[str] = None,
        analytic_id: Optional[str] = None,
        all_analytics: bool = False,
        context: Optional[ThreatContext] = None,
        max_steps: int = 4,
    ) -> list[ChainRule]:
        """Every correlation rule ATT&CK supports: attack chains and count thresholds."""
        return (
            self.generate_chains(technique, platform, analytic_id, all_analytics, context, max_steps)
            + self.generate_count_rules(technique, platform, analytic_id, all_analytics, context)
        )

    def generate_chains(
        self,
        technique: Technique,
        platform: Optional[str] = None,
        analytic_id: Optional[str] = None,
        all_analytics: bool = False,
        context: Optional[ThreatContext] = None,
        max_steps: int = 4,
    ) -> list[ChainRule]:
        """Temporal correlation rules from ATT&CK's multi-telemetry analytics.

        An analytic such as "a process opens lsass.exe with full access and
        subsequently writes a dump file" names several log sources.  A
        ``temporal`` correlation fires when all of them occur for the same host
        (or account) inside ATT&CK's own time window.

        Each step must carry behavioural content of its own - values are never
        repeated across steps - and at least two such steps are required.
        """
        chains = [
            chain
            for strategy, analytic in self._matching_analytics(technique, platform, analytic_id, context)
            if (chain := self._build_chain(technique, strategy, analytic, context, max_steps))
        ]
        chains.sort(key=lambda c: (c.quality.rank, c.provenance.confidence, len(c.steps)), reverse=True)
        LOG.info("Generated %d chain rule(s) for %s", len(chains), technique.id)
        return chains if all_analytics else chains[:1]

    def generate_count_rules(
        self,
        technique: Technique,
        platform: Optional[str] = None,
        analytic_id: Optional[str] = None,
        all_analytics: bool = False,
        context: Optional[ThreatContext] = None,
    ) -> list[ChainRule]:
        """``event_count`` / ``value_count`` rules where ATT&CK describes volume.

        "Repeated failed logons", "a burst of discovery API calls", "logins to
        multiple accounts from one IP" are not single-event behaviours; a
        threshold correlation over the base event expresses them.  ATT&CK rarely
        states the number, so thresholds are defaults unless its text gives one.
        """
        rules = [
            rule
            for strategy, analytic in self._matching_analytics(technique, platform, analytic_id, context)
            if (rule := self._build_count_rule(technique, strategy, analytic, context))
        ]
        rules.sort(key=lambda r: (r.quality.rank, r.provenance.confidence), reverse=True)
        LOG.info("Generated %d count rule(s) for %s", len(rules), technique.id)
        return rules if all_analytics else rules[:1]

    def telemetry_sources(self, analytic: Analytic, platform: Optional[str]) -> list[TelemetrySource]:
        """An analytic's usable log sources, merged per Sigma logsource."""
        cache_key = ("sources", analytic.stix_id, platform)
        if cache_key not in self._cache:
            self._cache[cache_key] = self._telemetry_sources(analytic, platform)
        return self._cache[cache_key]

    def _telemetry_sources(self, analytic: Analytic, platform: Optional[str]) -> list[TelemetrySource]:
        groups: dict[tuple, dict[str, Any]] = {}
        for position, log_source in enumerate(analytic.log_sources):
            mapping = resolve_telemetry(log_source.name, log_source.channel, log_source.data_component, platform)
            if not mapping.is_usable:
                continue
            key = (mapping.logsource.describe(), tuple(sorted(mapping.roles.items())),
                   tuple(sorted(mapping.base_selection)))
            group = groups.setdefault(key, {"mappings": [], "channels": [], "position": position})
            group["mappings"].append(mapping)
            if log_source.channel:
                group["channels"].append(log_source.channel)

        sources: list[TelemetrySource] = []
        for group in groups.values():
            mappings: list[TelemetryMapping] = group["mappings"]
            first = mappings[0]
            if len(mappings) > 1:
                labels = list(dict.fromkeys(m.source for m in mappings))
                source_label = "; ".join(labels[:3]) + (f" (+{len(labels) - 3} more)" if len(labels) > 3 else "")
                first = TelemetryMapping(
                    logsource=first.logsource,
                    fields=first.fields,
                    base_selection=_merge_base_selections([m.base_selection for m in mappings]),
                    roles=dict(first.roles),
                    confidence=max(m.confidence for m in mappings),
                    source=source_label,
                    notes=tuple(dict.fromkeys(note for m in mappings for note in m.notes)),
                )
            sources.append(TelemetrySource(first, group["channels"], group["position"]))
        sources.sort(key=lambda source: source.position)
        return sources

    # -- candidate selection ----------------------------------------------- #
    def _matching_analytics(self, technique: Technique, platform: Optional[str], analytic_id: Optional[str],
                            context: Optional[ThreatContext] = None) -> list[tuple[DetectionStrategy, Analytic]]:
        chosen = self._requested_platform(technique, platform)
        matches = []
        for strategy in technique.detection_strategies:
            for analytic in strategy.analytics:
                if analytic_id and analytic.id.upper() != analytic_id.upper():
                    continue
                if not analytic_id and chosen and analytic.platforms and not any(
                    p.lower() == chosen.lower() for p in analytic.platforms
                ):
                    continue
                matches.append((strategy, analytic))
        if context and not chosen and not analytic_id:
            # Correlation rules are extras: none at all beats one for a platform
            # the software does not run on.
            matches = [(strategy, analytic) for strategy, analytic in matches if context.fits(analytic)]
        return matches

    def _requested_platform(self, technique: Technique, platform: Optional[str]) -> Optional[str]:
        chosen = pick_platform(technique, platform) if platform else None
        if chosen and not any(p.lower() == chosen.lower() for p in technique.platforms):
            LOG.warning(
                "ATT&CK does not list %s as a platform for %s (it lists: %s)",
                chosen, technique.id, ", ".join(technique.platforms) or "none",
            )
        return chosen

    def _candidates(
        self,
        technique: Technique,
        platform: Optional[str],
        analytic_id: Optional[str],
        context: Optional[ThreatContext] = None,
        skip_mapping: Optional[Callable[[TelemetryMapping], bool]] = None,
    ) -> list[_Candidate]:
        """The best candidate per analytic, ranked best first."""
        candidates: list[_Candidate] = []
        for strategy in technique.detection_strategies:
            for analytic in strategy.analytics:
                if analytic_id and analytic.id.upper() != analytic_id.upper():
                    continue
                platform_match = (
                    not platform
                    or not analytic.platforms
                    or any(p.lower() == platform.lower() for p in analytic.platforms)
                )
                if analytic_id is None and platform and not platform_match:
                    continue
                analytic_platform = analytic.platforms[0] if analytic.platforms else platform
                pool = self._mine(technique, analytic, context)

                best: Optional[_Candidate] = None
                best_fitting: Optional[_Candidate] = None
                for source in self.telemetry_sources(analytic, analytic_platform):
                    if skip_mapping and skip_mapping(source.mapping):
                        continue
                    candidate = self._evaluate(technique, strategy, analytic, source, pool,
                                               analytic_platform, platform_match)
                    if best is None or candidate.sort_key > best.sort_key:
                        best = candidate
                    if (context and context.fits(analytic, source.mapping.logsource.product)
                            and (best_fitting is None or candidate.sort_key > best_fitting.sort_key)):
                        best_fitting = candidate
                if best is not None:
                    candidates.append(best_fitting or best)

        if candidates and context and context.platforms and not platform and not analytic_id:
            # Mimikatz runs on Windows: a Linux auditd rule is not a Mimikatz detection.
            fitting = [candidate for candidate in candidates
                       if context.fits(candidate.analytic, candidate.mapping.logsource.product)]
            if fitting:
                candidates = fitting
            else:
                for candidate in candidates:
                    candidate.notes.append(
                        f"ATT&CK lists {context.label} as running on {', '.join(context.platforms)}, but has no "
                        f"analytic for this technique there; this rule watches {candidate.platform or 'another platform'} "
                        "instead - check that it applies."
                    )
        if candidates:
            candidates.sort(key=lambda candidate: candidate.sort_key, reverse=True)
            return candidates
        if analytic_id:
            return []

        # Legacy bundles (ATT&CK <= v17) or techniques with no analytics at all.
        fallback, fallback_platform = self._legacy_mapping(technique, platform)
        if fallback and fallback.is_usable and not (skip_mapping and skip_mapping(fallback)):
            source = TelemetrySource(fallback, [], 0)
            return [self._evaluate(technique, None, None, source, self._mine(technique, None, context),
                                   fallback_platform, True)]
        return []

    def _evaluate(self, technique: Technique, strategy: Optional[DetectionStrategy], analytic: Optional[Analytic],
                  source: TelemetrySource, pool: Artefacts, platform: Optional[str],
                  platform_match: bool) -> _Candidate:
        artefacts = self._source_artefacts(source, pool)
        detection, notes = self._build_detection(source.mapping, artefacts, technique)
        return _Candidate(
            strategy=strategy,
            analytic=analytic,
            source=source,
            artefacts=artefacts,
            platform=platform,
            detection=detection,
            notes=notes,
            quality=assess_quality(detection),
            score=self._telemetry_score(source.mapping, artefacts, source.position),
            platform_match=platform_match,
        )

    def _insufficient_message(self, technique: Technique, candidates: list[_Candidate]) -> str:
        telemetry = list(dict.fromkeys(c.mapping.logsource.describe() for c in candidates))
        knobs = list(dict.fromkeys(name for c in candidates if c.analytic for name, _ in c.analytic.mutable_elements))
        message = (
            f"{technique.id} ({technique.name}): ATT&CK names telemetry to watch "
            f"({', '.join(telemetry[:4])}) but gives no concrete values to detect on, so no rule was "
            "written. Use --include-skeletons to write a skeleton rule to complete by hand."
        )
        if knobs:
            message += f" ATT&CK's tuning knobs suggest where to start: {', '.join(knobs[:5])}."
        return message

    #: Tie-break order when ATT&CK gives no analytic to choose a platform from.
    #: Endpoint telemetry first: it carries the most detection signal and Sigma's
    #: logsource vocabulary is richest there.  Override with --platform.
    _PLATFORM_PREFERENCE = (
        "windows", "linux", "macos", "identity provider", "office suite", "iaas",
        "saas", "containers", "esxi", "network devices",
    )

    def _ordered_platforms(self, technique: Technique) -> list[Optional[str]]:
        if not technique.platforms:
            return [None]
        preference = self._PLATFORM_PREFERENCE
        return sorted(
            technique.platforms,
            key=lambda name: preference.index(name.lower()) if name.lower() in preference else len(preference),
        )

    def _mine(self, technique: Technique, analytic: Optional[Analytic],
              context: Optional[ThreatContext] = None) -> Artefacts:
        """Evidence shared by all of an analytic's log sources."""
        cache_key = ("pool", technique.stix_id, analytic.stix_id if analytic else None,
                     context.label if context else None, context.procedures if context else ())
        if cache_key in self._cache:
            return self._cache[cache_key]
        self._cache[cache_key] = extract_artefacts(
            # Procedure examples first: they describe real observed tradecraft.
            "\n".join(context.procedures) if context else "",
            analytic.description if analytic else "",
            "\n".join(description for _, description in (analytic.mutable_elements if analytic else ())),
            technique.description,
            technique.legacy_detection,
            limit=self.artefact_limit,
        )
        return self._cache[cache_key]

    def _source_artefacts(self, source: TelemetrySource, pool: Artefacts) -> Artefacts:
        """A log source's own channel text first, then the shared evidence."""
        cache_key = ("source-artefacts", id(source), id(pool))
        if cache_key not in self._cache:
            own = extract_artefacts(*source.channels, limit=self.artefact_limit) if source.channels else Artefacts()
            # Keep the objects alive so their ids cannot be reused by new ones.
            self._cache[cache_key] = (own.merged_with(pool, self.artefact_limit), source, pool)
        return self._cache[cache_key][0]

    def _telemetry_score(self, mapping: TelemetryMapping, artefacts: Artefacts, position: int = 0) -> float:
        """Rank log sources of equal quality.

        * **confidence** - did ATT&CK name the exact event, or did we infer it?
        * **position**   - ATT&CK lists an analytic's primary telemetry first.
        * **fit**        - can this source carry what was mined?  Registry keys
          belong in a registry rule, not a process-creation rule.
        """
        roles = mapping.roles
        placed = place_artefacts(artefacts, mapping)
        fit = 0.0
        if placed.registry_keys and "registry_key" in roles:
            fit += 2.0
        if placed.targets and "target_image" in roles:
            fit += 2.0
        if placed.libraries and "loaded_image" in roles:
            # Weaker than it looks: prose DLLs are often ubiquitous (shell32.dll).
            fit += 1.0
        if placed.paths and "file" in roles:
            fit += 1.0
        if placed.actors and "image" in roles:
            fit += 1.0
        if placed.ports and "port" in roles:
            fit += 1.0
        if placed.native_content and ("command_line" in roles or "script" in roles):
            fit += 1.0
        if placed.access_masks and "access_mask" in roles:
            fit += 0.5
        if mapping.base_selection:
            fit += 0.5  # ATT&CK pinned a concrete event id / API operation

        position_bonus = max(0.0, 2.0 - 0.75 * position)
        return mapping.confidence * 10 + position_bonus + fit * 0.6

    def _legacy_mapping(
        self, technique: Technique, platform: Optional[str]
    ) -> tuple[Optional[TelemetryMapping], Optional[str]]:
        """Telemetry for techniques ATT&CK ships no analytic for.

        Covers two cases: a pinned pre-v18 bundle (where the hints live in
        ``x_mitre_data_sources``) and techniques with no detection strategy.
        """
        platforms = [platform] if platform else self._ordered_platforms(technique)
        best: Optional[TelemetryMapping] = None
        best_platform: Optional[str] = None
        for candidate_platform in platforms:
            for data_source in technique.legacy_data_sources:
                # Legacy strings look like "Process: Process Creation".
                component = data_source.split(":", 1)[-1].strip()
                mapping = resolve_telemetry(None, None, component, candidate_platform)
                if mapping.is_usable and (best is None or mapping.confidence > best.confidence):
                    best, best_platform = mapping, candidate_platform
            mapping = resolve_telemetry(None, None, None, candidate_platform)
            if mapping.is_usable and (best is None or mapping.confidence > best.confidence):
                best, best_platform = mapping, candidate_platform
        return best, best_platform

    # -- rule assembly ----------------------------------------------------- #
    def _build_rule(self, technique: Technique, candidate: _Candidate,
                    context: Optional[ThreatContext] = None) -> SigmaRule:
        mapping, quality, analytic, strategy = candidate.mapping, candidate.quality, candidate.analytic, candidate.strategy
        provenance = RuleProvenance(
            technique_id=technique.id,
            technique_name=technique.name,
            attack_version=self.attack_version,
            platform=candidate.platform,
            strategy_id=strategy.id if strategy else None,
            strategy_name=strategy.name if strategy else None,
            analytic_id=analytic.id if analytic else None,
            analytic_description=analytic.description if analytic else "",
            telemetry_source=mapping.source,
            logsource_label=mapping.logsource.describe(),
            confidence=mapping.confidence,
            artefact_counts=self._artefact_counts(candidate.artefacts),
            mutable_elements=analytic.mutable_elements if analytic else (),
            notes=tuple(mapping.notes) + tuple(candidate.notes) + self._quality_notes(quality),
            threat_label=context.label if context else None,
            procedure_count=len(context.procedures) if context else 0,
            quality=quality,
        )

        tags = self._build_tags(technique, context)
        if quality.tier == "weak":
            tags.append("detection.threat-hunting")
        title = self._build_title(technique, mapping)
        rule = SigmaRule(
            title=title,
            id=self._rule_id(technique, analytic, mapping, title, context),
            status="unsupported" if quality.tier == "placeholder" else self.status,
            description=self._build_description(technique, strategy, analytic, mapping, context),
            references=self._build_references(technique, strategy, analytic, context),
            author=self.author,
            date=today_iso(),
            tags=tags,
            logsource=mapping.logsource.as_dict(),
            detection=candidate.detection,
            fields=list(mapping.fields),
            falsepositives=self._build_falsepositives(technique, analytic, candidate.artefacts, mapping,
                                                      [candidate.detection]),
            level=self._build_level(technique, quality, mapping),
            provenance=provenance,
            key_order=self.key_order,
        )
        rule.banner = self._build_banner(rule)
        return rule

    @staticmethod
    def _quality_notes(quality: RuleQuality) -> tuple[str, ...]:
        if quality.tier == "weak":
            return (
                f"Weak rule: {quality.reasons[0]}. It is tagged detection.threat-hunting and capped at "
                "level low - use it to hunt, or add the constraint that separates the technique from "
                "normal activity. Where ATT&CK describes volume, --chains adds a count-based version.",
            )
        if quality.tier == "placeholder":
            return (
                "Skeleton rule: ATT&CK names this telemetry but no concrete values. Replace "
                "selection_todo with an artefact you have observed - until then the rule matches nothing.",
            )
        return ()

    # -- individual fields ------------------------------------------------- #
    @staticmethod
    def _source_hint(mapping: TelemetryMapping) -> str:
        """Human label for a log source: "Process Creation", "AWS CloudTrail"."""
        logsource = mapping.logsource
        if logsource.category:
            return _CATEGORY_LABELS.get(logsource.category, logsource.category.replace("_", " ").title())
        if logsource.product and logsource.service:
            product = _PRODUCT_LABELS.get(logsource.product, logsource.product.title())
            service = _SERVICE_LABELS.get(logsource.service, logsource.service.replace("_", " ").title())
            return f"{product} {service}"
        return (logsource.product or logsource.service or "Telemetry").title()

    def _build_title(self, technique: Technique, mapping: TelemetryMapping) -> str:
        name = re.sub(r"\s*/\s*", " or ", technique.name)
        title = re.sub(r"\s{2,}", " ", f"Potential {name} Activity Via {self._source_hint(mapping)}")
        if len(title) > 120:
            title = title[:117].rstrip() + "..."
        return title

    # -- correlation rules --------------------------------------------------- #
    #: Field that identifies "the same machine" per Sigma product.
    _HOST_FIELDS = {"windows": "Computer", "linux": "host", "macos": "host", "esxi": "host",
                    "zeek": "id.orig_h", "cisco": "host"}
    _ORDER_WORDS = re.compile(
        r"\b(followed by|subsequently|then|afterwards|after which|leading to|preceded by|prior to|sequence)\b",
        re.IGNORECASE,
    )
    _DURATION_RE = re.compile(
        r"(\d+)\s*-?\s*(seconds?|secs?|minutes?|mins?|hours?|hrs?|days?)\b", re.IGNORECASE
    )
    #: Things that can be counted in a log - what "a high number of ..." must be about.
    _COUNTABLE = (
        r"(?:events?|attempts?|requests?|logins?|logons?|sign-?ins?|queries|lookups?|calls?|connections?|"
        r"commands?|files?|e-?mails?|messages?|hosts?|systems?|destinations?|ips?|ports?|accounts?|users?|"
        r"operations?|authentications?|failures?|errors?|prompts?|challenges?|pushes|notifications?|"
        r"executions?|processes|invocations?|enumerations?|reads?|writes?|downloads?|uploads?|"
        r"modifications?|deletions?|(?:re-?)?creations?|api calls?)"
    )
    #: Wording that means "how many", not "how big" or "how often it is abused".
    #: Every alternative needs an amount *and* something countable: "a high volume
    #: of failed logons", "number of unique destination IPs", "queried frequently".
    #: Bare "volume(s)" is a disk volume as often as an amount (``/Volumes/``,
    #: "mounted volumes"), "frequently abused" describes the technique, and a
    #: bare "threshold" is as often a size ("threshold for script block length").
    _VOLUME_RE = re.compile(
        r"\b(?:high|large|huge|excessive|unusual(?:ly high)?|abnormal(?:ly high)?|increased|elevated|significant)"
        r"[\s-]+(?:volumes?|frequency|rates?|numbers?|counts?|amounts?)\b"
        r"|\b(?:number|rate|frequency|volume|count)s?\s+of\s+(?:[\w/-]+\s+){0,2}" + _COUNTABLE + r"\b"
        r"|\b(?:rate|volume)/(?:rate|volume)\s+of\s+(?:[\w/-]+\s+){0,2}" + _COUNTABLE + r"\b"
        r"|\b(?:executed|run|invoked|called|queried|accessed|requested|issued|sent)\s+(?:very\s+)?frequently\b"
        r"|\b(?:frequent|excessive|repeated(?:ly)?|rapid|successive)\s+(?:[\w-]+\s+)?" + _COUNTABLE + r"\b"
        r"|\b(?:call|request|query|connection|login|logon|execution|event|access)s?\s+(?:frequency|rate)\b"
        r"|\b(?:bursts?|spikes?|flood(?:s|ing)?|brute[\s-]?forc\w*|spray(?:ing|s)?|by volume|in rapid succession)\b"
        r"|\bmultiple\s+(?:failed|failures?|attempts?|requests?|logins?|logons?|prompts?|queries|calls?|"
        r"connections?|authentications?)\b"
        r"|\bthreshold\s+(?:of|for)\s+(?:failed|failures?|attempts?|requests?|calls?|events?|logins?|logons?|"
        r"queries|connections?|prompts?)\b",
        re.IGNORECASE,
    )
    #: Tuning-knob names that are counts by construction ("ScanRateThreshold").
    #: Case-sensitive on purpose.  Byte and packet rates ("OutboundDataRateThreshold",
    #: "PacketRateThreshold") are not event counts a Sigma correlation can express.
    _VOLUME_KNOB_RE = re.compile(
        r"(?<!Data)(?<!Traffic)(?<!Packet)(?<!Byte)(?<!Bandwidth)(?<!Volume)"
        r"(?:(?<=[a-z])|^)(?:Rate|Frequency|Count|Attempts?|Failures?)Threshold\b"
    )
    #: Wording that marks the amount as normal ("allowlist of high-volume, benign domains").
    _BENIGN_NEAR_RE = re.compile(
        r"\b(?:benign|allow-?list\w*|whitelist\w*|known[- ]good|legitimate|approved|trusted)\b", re.IGNORECASE
    )
    _DISTINCT_RE = re.compile(
        r"\b(?:distinct|unique|different|multiple|many)\s+(accounts?|users?|usernames?|identities|hosts?|systems?|"
        r"machines?|ips?|ip addresses|addresses|destinations?|targets?|files?)\b",
        re.IGNORECASE,
    )
    _THRESHOLD_RE = re.compile(
        r"(?:>=|>|≥|at least|more than|over|exceed\w*)?\s*\b(\d{1,3})\s+(?:failed\s+|unique\s+|distinct\s+|different\s+)?"
        r"(?:failures?|attempts?|requests?|calls?|events?|logins?|logons?|times|connections?|queries|errors?|"
        r"prompts?|pushes?|accounts?|users?|hosts?|files?)\b",
        re.IGNORECASE,
    )
    DEFAULT_TIMESPAN = "10m"
    MAX_TIMESPAN_SECONDS = 86400

    def _group_field(self, mapping: TelemetryMapping) -> tuple[str, str]:
        """(kind, field) that groups a step's events: a host, or an account for cloud logs."""
        product = (mapping.logsource.product or "").lower()
        if product in self._HOST_FIELDS:
            return "host", self._HOST_FIELDS[product]
        user_field = mapping.roles.get("user")
        return ("account", user_field) if user_field else ("host", "host")

    @classmethod
    def parse_timespan(cls, texts: Iterable[str]) -> Optional[tuple[str, str]]:
        """First duration in ``texts`` as a Sigma timespan, plus the text it came from."""
        seconds_per = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        for text in texts:
            for match in cls._DURATION_RE.finditer(text or ""):
                amount, unit = int(match.group(1)), match.group(2).lower()
                letter = "m" if unit.startswith("min") else unit[0]
                # Anything beyond a day is a threshold ("backdated by >90 days"),
                # not a window in which attack steps unfold.
                if 0 < amount * seconds_per[letter] <= cls.MAX_TIMESPAN_SECONDS:
                    return f"{amount}{letter}", text
        return None

    @classmethod
    def parse_threshold(cls, text: str) -> Optional[int]:
        """A count ATT&CK states ("more than 20 failed logons"), within sane bounds."""
        for match in cls._THRESHOLD_RE.finditer(text or ""):
            value = int(match.group(1))
            if 2 <= value <= 500:
                return value
        return None

    @classmethod
    def volume_phrase(cls, fragments: Iterable[str], knob_names: Iterable[str] = ()) -> Optional[str]:
        """The first wording in ``fragments`` that describes an amount of activity.

        Each fragment (a sentence, a tuning knob, a log-source channel) is checked
        on its own, and a match next to "benign"/"allowlist" wording is ignored.
        """
        for name in knob_names:
            match = cls._VOLUME_KNOB_RE.search(name or "")
            if match:
                return name
        for fragment in fragments:
            for match in cls._VOLUME_RE.finditer(fragment or ""):
                window = fragment[max(0, match.start() - 40):match.end() + 40]
                if not cls._BENIGN_NEAR_RE.search(window):
                    return match.group(0)
        return None

    def _timespan_for(self, analytic: Analytic) -> tuple[str, str, bool]:
        time_texts = [description for name, description in analytic.mutable_elements
                      if re.search(r"time|window|interval|period", name, re.IGNORECASE)]
        parsed = self.parse_timespan(time_texts + [analytic.description])
        if parsed:
            return parsed[0], parsed[1], True
        return self.DEFAULT_TIMESPAN, "", False

    @staticmethod
    def _behavioural_values(detection: dict[str, Any]) -> set[str]:
        return {
            normalise_value(value)
            for name, block in detection.items() if name not in _NON_BEHAVIOURAL
            for value in selection_values(block)
        }

    def _build_chain(self, technique: Technique, strategy: DetectionStrategy, analytic: Analytic,
                     context: Optional[ThreatContext], max_steps: int) -> Optional[ChainRule]:
        platform = analytic.platforms[0] if analytic.platforms else None
        pool = self._mine(technique, analytic, context)

        sources = self.telemetry_sources(analytic, platform)
        if not sources:
            return None
        # Correlating a host-scoped event with an account-scoped one is meaningless,
        # so the chain keeps to the scope of ATT&CK's primary (first) source.
        scope_kind = self._group_field(sources[0].mapping)[0]
        sources = [source for source in sources if self._group_field(source.mapping)[0] == scope_kind]

        # Values are handed out without repetition.  Sources whose rule has a subject
        # selection (a registry key, a target process, a path) claim first, so a Run
        # key lands in the registry step rather than as command-line text in the
        # process step that happens to be listed earlier.
        artefacts_by_source = {id(source): self._source_artefacts(source, pool) for source in sources}

        def has_subject(source: TelemetrySource) -> bool:
            detection, _ = self._build_detection(source.mapping, artefacts_by_source[id(source)], technique)
            return any(name in _SUBJECT_SELECTIONS for name in detection)

        claim_order = sorted(sources, key=lambda source: (not has_subject(source), source.position))
        used: set[str] = set()
        accepted: list[tuple[TelemetrySource, dict[str, Any], RuleQuality]] = []
        for source in claim_order:
            detection, _ = self._build_detection(source.mapping, artefacts_by_source[id(source)], technique, exclude=used)
            quality = assess_quality(detection)
            # Each step needs a specific behavioural value of its own; a step that
            # only names an event type would make the correlation meaningless.
            if quality.signals < 1:
                continue
            used |= self._behavioural_values(detection)
            accepted.append((source, detection, quality))

        picked = sorted(accepted, key=lambda item: item[0].position)[:max_steps]
        first_kind = scope_kind
        if len(picked) < 2:
            return None

        steps: list[ChainStep] = []
        for number, (source, detection, quality) in enumerate(picked, start=1):
            mapping = source.mapping
            label = mapping.logsource.category or mapping.logsource.service or mapping.logsource.product or "event"
            name = f"step{number}_{slugify(label, 30)}"
            steps.append(ChainStep(
                name=name,
                title=f"{technique.name} - Step {number}: {self._source_hint(mapping)}",
                id=self._rule_id(technique, analytic, mapping, name, context, kind=f"chain-step-{number}"),
                logsource=mapping.logsource.as_dict(),
                detection=detection,
                telemetry_source=mapping.source,
                logsource_label=mapping.logsource.describe(),
                confidence=mapping.confidence,
                group_field=self._group_field(mapping)[1],
                quality=quality,
            ))

        timespan, timespan_source, from_attack = self._timespan_for(analytic)
        group_fields = {step.group_field for step in steps}
        correlation: dict[str, Any] = {"type": "temporal", "rules": [step.name for step in steps]}
        correlation["group-by"] = [steps[0].group_field] if len(group_fields) == 1 else [first_kind]
        correlation["timespan"] = timespan
        if len(group_fields) > 1:
            correlation["aliases"] = {first_kind: {step.name: step.group_field for step in steps}}

        weakest = min(steps, key=lambda step: step.quality.rank).quality
        chain_quality = RuleQuality(
            "strong" if weakest.rank >= TIER_ORDER.index("moderate") else "moderate",
            len(steps),
            (f"{len(steps)} correlated behaviours with distinct values; weakest step is {weakest.tier}",),
        )

        hints = [self._source_hint(source.mapping) for source, _, _ in picked]
        name = re.sub(r"\s*/\s*", " or ", technique.name)
        title = f"Potential {name} Attack Chain Via {', '.join(hints[:-1])} And {hints[-1]}"
        if len(steps) > 3 or len(title) > 100:
            title = f"Potential {name} Attack Chain Via {len(steps)} Correlated Log Sources"
        scope = "host" if first_kind == "host" else "account"

        description_parts = [
            f"Draft correlation for {technique.id} ({technique.name}). ATT&CK analytic {analytic.id} "
            f"(strategy {strategy.id}) describes this technique as {len(steps)} observable behaviours; "
            f"this rule fires when all of them occur on the same {scope} within {timespan}.",
            "Steps: " + "; ".join(f"{i}) {hint}" for i, hint in enumerate(hints, start=1)) + ".",
        ]
        if context and context.procedures:
            description_parts.append(f"Observed use by {context.label}: " + first_sentences(context.procedures[0], 1, 300))
        if analytic.description:
            description_parts.append("ATT&CK analytic: " + first_sentences(analytic.description, 2, 380))
        description_parts.append(
            "Generated draft - step selections were mined from ATT&CK and must be validated "
            "against real telemetry before this rule is deployed."
        )

        notes = [self._timespan_note(timespan, timespan_source, from_attack)]
        if self._ORDER_WORDS.search(analytic.description):
            notes.append(
                "ATT&CK describes these behaviours as a sequence. Once you have confirmed the order in "
                "your telemetry, switch `type` to `temporal_ordered` and list the rules in that order."
            )
        notes.append(f"Events are grouped by {', '.join(sorted(group_fields))}; that field must be populated in "
                     "every step's events in your pipeline.")
        notes.append("Not every SIEM backend supports Sigma correlation rules - check yours before converting.")

        best = max((source.mapping for source, _, _ in picked), key=lambda m: m.confidence)
        artefacts = self._source_artefacts(picked[0][0], pool)
        level = self._build_level(technique, chain_quality, best)
        if not self.level_override:
            level = LEVEL_ORDER[min(len(LEVEL_ORDER) - 1, LEVEL_ORDER.index(level) + 1)]

        provenance = RuleProvenance(
            technique_id=technique.id,
            technique_name=technique.name,
            attack_version=self.attack_version,
            platform=platform,
            strategy_id=strategy.id,
            strategy_name=strategy.name,
            analytic_id=analytic.id,
            analytic_description=analytic.description,
            telemetry_source=" + ".join(step.telemetry_source for step in steps),
            logsource_label=" + ".join(step.logsource_label for step in steps),
            confidence=min(step.confidence for step in steps),
            artefact_counts=self._artefact_counts(artefacts),
            mutable_elements=analytic.mutable_elements,
            notes=tuple(notes),
            threat_label=context.label if context else None,
            procedure_count=len(context.procedures) if context else 0,
            quality=chain_quality,
        )
        chain = ChainRule(
            title=title,
            id=self._rule_id(technique, analytic, best, title, context, kind="chain"),
            status=self.status,
            description=wrap_text("\n".join(description_parts), width=96),
            references=self._build_references(technique, strategy, analytic, context),
            author=self.author,
            date=today_iso(),
            tags=self._build_tags(technique, context),
            correlation=correlation,
            falsepositives=self._build_falsepositives(technique, analytic, artefacts, best,
                                                      [step.detection for step in steps]),
            level=level,
            steps=steps,
            provenance=provenance,
            kind="chain",
        )
        chain.banner = self._build_chain_banner(chain)
        return chain

    def _count_spec(self, mapping: TelemetryMapping, text: str) -> Optional[dict[str, Any]]:
        """Decide event_count vs value_count, the fields, and the threshold."""
        roles = mapping.roles
        _, host_field = self._group_field(mapping)
        distinct = self._DISTINCT_RE.search(text)
        if distinct:
            entity = distinct.group(1).lower()
            role = ("user" if entity.startswith(("account", "user", "identit"))
                    else "file" if entity.startswith("file") else "destination")
            counted = roles.get(role)
            if counted:
                others = [roles.get("destination")] if role == "user" else [roles.get("user")]
                group = next((f for f in others + [roles.get("image"), host_field] if f and f != counted), None)
                if group:
                    stated = self.parse_threshold(text)
                    return {"type": "value_count", "field": counted, "group_by": group, "entity": entity,
                            "threshold": stated or self.DEFAULT_DISTINCT_THRESHOLD, "stated": bool(stated)}
        group = roles.get("user") or host_field
        if not group:
            return None
        stated = self.parse_threshold(text)
        return {"type": "event_count", "group_by": group,
                "threshold": stated or self.DEFAULT_EVENT_THRESHOLD, "stated": bool(stated)}

    def _build_count_rule(self, technique: Technique, strategy: DetectionStrategy, analytic: Analytic,
                          context: Optional[ThreatContext]) -> Optional[ChainRule]:
        platform = analytic.platforms[0] if analytic.platforms else None
        knob_text = " ".join(f"{name} {description}" for name, description in analytic.mutable_elements)
        knob_names = [name for name, _ in analytic.mutable_elements]
        fragments = split_sentences(analytic.description) + [
            f"{name}: {description}" for name, description in analytic.mutable_elements
        ]
        pool = self._mine(technique, analytic, context)

        best: Optional[tuple] = None
        for source in self.telemetry_sources(analytic, platform):
            text = " ".join([analytic.description, knob_text, *source.channels])
            volume = self.volume_phrase(fragments + list(source.channels), knob_names)
            if not volume:
                continue
            artefacts = self._source_artefacts(source, pool)
            detection, _ = self._build_detection(source.mapping, artefacts, technique)
            base_quality = assess_quality(detection)
            if base_quality.tier == "placeholder":
                continue
            # Volume is the signal for broad events ("repeated failed logons"). For a
            # base rule that is already specific, a threshold only adds value when
            # this log source's own ATT&CK text talks about volume.
            if base_quality.tier != "weak" and not self.volume_phrase(source.channels):
                continue
            spec = self._count_spec(source.mapping, text)
            if spec is None:
                continue
            rank = (base_quality.rank, self._telemetry_score(source.mapping, artefacts, source.position))
            if best is None or rank > best[0]:
                best = (rank, source, detection, base_quality, spec, volume, artefacts)
        if best is None:
            return None

        _, source, detection, base_quality, spec, volume_phrase, artefacts = best
        mapping = source.mapping
        hint = self._source_hint(mapping)
        label = mapping.logsource.category or mapping.logsource.service or mapping.logsource.product or "event"
        step_name = f"base_{slugify(label, 30)}"
        step = ChainStep(
            name=step_name,
            title=f"{technique.name} - Counted Event: {hint}",
            id=self._rule_id(technique, analytic, mapping, step_name, context, kind="count-base"),
            logsource=mapping.logsource.as_dict(),
            detection=detection,
            telemetry_source=mapping.source,
            logsource_label=mapping.logsource.describe(),
            confidence=mapping.confidence,
            group_field=spec["group_by"],
            quality=base_quality,
        )

        timespan, timespan_source, from_attack = self._timespan_for(analytic)
        condition: dict[str, Any] = {"gte": spec["threshold"]}
        if spec["type"] == "value_count":
            condition = {"field": spec["field"], "gte": spec["threshold"]}
        correlation = {
            "type": spec["type"],
            "rules": [step_name],
            "group-by": [spec["group_by"]],
            "timespan": timespan,
            "condition": condition,
        }

        rank = max(base_quality.rank, TIER_ORDER.index("moderate"))
        count_quality = RuleQuality(
            TIER_ORDER[rank], max(base_quality.signals, 1),
            (f"{spec['type']} threshold over a {base_quality.tier} base event",),
        )

        name = re.sub(r"\s*/\s*", " or ", technique.name)
        if spec["type"] == "value_count":
            entity = spec["entity"].rstrip("s").title() + "s"
            title = f"Potential {name} Across Multiple {entity} Via {hint}"
            what = f"{spec['threshold']} or more distinct values of {spec['field']}"
        else:
            title = f"Potential {name} Burst Via {hint}"
            what = f"{spec['threshold']} or more matching events"
        if len(title) > 120:
            title = title[:117].rstrip() + "..."

        description_parts = [
            f"Draft threshold correlation for {technique.id} ({technique.name}). ATT&CK analytic {analytic.id} "
            f"(strategy {strategy.id}) describes volume (\"{volume_phrase}\"); this rule fires when {what} "
            f"occur for the same {spec['group_by']} within {timespan}.",
        ]
        if analytic.description:
            description_parts.append("ATT&CK analytic: " + first_sentences(analytic.description, 2, 380))
        description_parts.append(
            "Generated draft - the threshold and base selection must be tuned against real telemetry "
            "before this rule is deployed."
        )

        notes = [
            (f"Threshold {spec['threshold']} is stated in ATT&CK's text." if spec["stated"] else
             f"ATT&CK describes volume but gives no number; {spec['threshold']} is a default - "
             "baseline your normal activity and tune it."),
            self._timespan_note(timespan, timespan_source, from_attack),
            f"Events are counted per {spec['group_by']}; that field must be populated in your pipeline.",
            "Not every SIEM backend supports Sigma correlation rules - check yours before converting.",
        ]

        provenance = RuleProvenance(
            technique_id=technique.id,
            technique_name=technique.name,
            attack_version=self.attack_version,
            platform=platform,
            strategy_id=strategy.id,
            strategy_name=strategy.name,
            analytic_id=analytic.id,
            analytic_description=analytic.description,
            telemetry_source=mapping.source,
            logsource_label=mapping.logsource.describe(),
            confidence=mapping.confidence,
            artefact_counts=self._artefact_counts(artefacts),
            mutable_elements=analytic.mutable_elements,
            notes=tuple(notes),
            threat_label=context.label if context else None,
            procedure_count=len(context.procedures) if context else 0,
            quality=count_quality,
        )
        rule = ChainRule(
            title=title,
            id=self._rule_id(technique, analytic, mapping, title, context, kind="count"),
            status=self.status,
            description=wrap_text("\n".join(description_parts), width=96),
            references=self._build_references(technique, strategy, analytic, context),
            author=self.author,
            date=today_iso(),
            tags=self._build_tags(technique, context),
            correlation=correlation,
            falsepositives=self._build_falsepositives(technique, analytic, artefacts, mapping, [detection]),
            level=self._build_level(technique, count_quality, mapping),
            steps=[step],
            provenance=provenance,
            kind="count",
        )
        rule.banner = self._build_chain_banner(rule)
        return rule

    @staticmethod
    def _timespan_note(timespan: str, source: str, from_attack: bool) -> str:
        if from_attack:
            return f"timespan {timespan} comes from ATT&CK: \"{first_sentences(source, 1, 120)}\""
        return f"ATT&CK gives no time window for this analytic; {timespan} is a default - tune it."

    def _build_chain_banner(self, chain: ChainRule) -> list[str]:
        provenance = chain.provenance
        correlation = chain.correlation
        divider = "-" * 74
        if chain.kind == "count":
            condition = correlation["condition"]
            counted = f"distinct {condition['field']}" if "field" in condition else "events"
            summary = (f"{correlation['type']}: {counted} >= {condition['gte']} within {correlation['timespan']}, "
                       f"per {', '.join(correlation['group-by'])}")
        else:
            summary = (f"{correlation['type']} over {correlation['timespan']}, "
                       f"grouped by {', '.join(correlation['group-by'])}")
        lines = [
            divider,
            f"DRAFT CORRELATION RULE - generated by sigma-generator v{__version__} on {chain.date}",
            divider,
            f"ATT&CK        : {provenance.technique_id} {provenance.technique_name}"
            + (f" (ATT&CK v{provenance.attack_version})" if provenance.attack_version else ""),
            f"Strategy      : {provenance.strategy_id} {provenance.strategy_name}",
            f"Analytic      : {provenance.analytic_id}" + (f" ({provenance.platform})" if provenance.platform else ""),
            f"Correlation   : {summary}",
            f"Quality       : {chain.quality.label}",
            f"Confidence    : {provenance.confidence:.2f} - {'weakest step; ' if chain.kind == 'chain' else ''}"
            f"{provenance.confidence_label}",
        ]
        if provenance.threat_label:
            lines.append(f"Threat context: {provenance.threat_label} - "
                         f"{provenance.procedure_count} ATT&CK procedure example(s) mined first")
        lines += ["", "Steps:" if chain.kind == "chain" else "Counted event:"]
        for number, step in enumerate(chain.steps, start=1):
            lines.append(f"  {number}. {step.name}: {step.telemetry_source} -> {step.logsource_label} "
                         f"[{step.confidence:.2f}, {step.quality.tier}]")
        lines += ["", "Notes:"]
        for note in provenance.notes:
            for index, chunk in enumerate(wrap_text(note, width=68).split("\n")):
                lines.append(f"  - {chunk}" if index == 0 else f"    {chunk}")
        if chain.kind == "count":
            steps_advice = [
                "  1. Validate the counted base event on its own against real telemetry.",
                "  2. Baseline normal volume, then set the threshold above it.",
                "  3. Confirm the group-by field exists in your pipeline.",
            ]
        else:
            steps_advice = [
                "  1. Validate each step on its own against real telemetry first.",
                "  2. Confirm the group-by field exists in every step's events.",
                "  3. Tune the timespan to how fast this behaviour unfolds in your estate.",
            ]
        lines += ["", "Before deploying:", *steps_advice, divider]
        return lines

    def _rule_id(self, technique: Technique, analytic: Optional[Analytic],
                 mapping: TelemetryMapping, title: str,
                 context: Optional[ThreatContext] = None, kind: str = "rule") -> str:
        if not self.deterministic:
            return str(uuid.uuid4())
        seed = "|".join([
            kind, technique.id, analytic.id if analytic else "-", mapping.logsource.describe(), title,
            context.label if context else "-",
        ])
        return str(uuid.uuid5(RULE_NAMESPACE, seed))

    def _build_description(self, technique: Technique, strategy: Optional[DetectionStrategy],
                           analytic: Optional[Analytic], mapping: TelemetryMapping,
                           context: Optional[ThreatContext] = None) -> str:
        parts: list[str] = []
        origin = f"Draft detection for {technique.id} ({technique.name})"
        if strategy and analytic:
            origin += f", derived from ATT&CK detection strategy {strategy.id} / analytic {analytic.id}"
        elif technique.legacy_data_sources:
            origin += ", derived from the ATT&CK data sources listed for this technique"
        parts.append(origin + ".")

        summary = first_sentences(technique.description, 2, 380)
        if summary:
            parts.append(summary)
        if context and context.procedures:
            parts.append(f"Observed use by {context.label}: " + first_sentences(context.procedures[0], 1, 300))
        if analytic and analytic.description:
            parts.append("ATT&CK analytic: " + first_sentences(analytic.description, 2, 380))
        parts.append(
            "Generated draft - the selection values below were mined from ATT&CK and must be "
            "validated against real telemetry before this rule is deployed."
        )
        return wrap_text("\n".join(parts), width=96)

    def _build_references(self, technique: Technique, strategy: Optional[DetectionStrategy],
                          analytic: Optional[Analytic], context: Optional[ThreatContext] = None) -> list[str]:
        references: list[str] = []
        for url in (technique.url, strategy.url if strategy else "", analytic.url if analytic else "",
                    context.url if context else ""):
            if url and url not in references:
                references.append(url)
        for source_name, url in technique.references:
            if source_name == "mitre-attack" or not url.startswith("http"):
                continue
            if url not in references:
                references.append(url)
            if len(references) >= 6:
                break
        return references

    def _build_tags(self, technique: Technique, context: Optional[ThreatContext] = None) -> list[str]:
        tags = [f"attack.{tactic}" for tactic in technique.tactics if tactic]
        if technique.parent_id and technique.is_subtechnique:
            tags.append(f"attack.{technique.parent_id.lower()}")
        tags.append(f"attack.{technique.id.lower()}")
        if context and context.sigma_tag:
            tags.append(context.sigma_tag)
        return list(dict.fromkeys(tags))

    def _build_falsepositives(self, technique: Technique, analytic: Optional[Analytic],
                              artefacts: Artefacts, mapping: TelemetryMapping,
                              detections: Iterable[dict[str, Any]] = ()) -> list[str]:
        entries: list[str] = []
        # Only name tools this rule actually matches on.
        matched = {normalise_value(value) for detection in detections
                   for block in detection.values() for value in selection_values(block)}
        tools = [actor.lstrip("\\/") for actor in place_artefacts(artefacts, mapping).actors
                 if normalise_value(actor) in matched]
        if tools:
            entries.append("Legitimate administrative or software-deployment use of " + ", ".join(tools[:3]))
        if analytic:
            for name, description in analytic.mutable_elements[:3]:
                short = first_sentences(description, 1, 110) or "tuning required"
                entries.append(f"Environment-specific tuning of {name}: {short}")
        entries.extend(self.default_falsepositives)
        return list(dict.fromkeys(entries))

    def _build_level(self, technique: Technique, quality: RuleQuality, mapping: TelemetryMapping) -> str:
        """Start from the ATT&CK tactic, then let the rule's quality pull it down."""
        if self.level_override:
            return self.level_override
        if quality.tier == "placeholder":
            return "informational"
        levels = [TACTIC_LEVEL.get(tactic, "medium") for tactic in technique.tactics] or ["medium"]
        level = max(levels, key=lambda value: VALID_LEVEL.index(value) if value in VALID_LEVEL else 2)
        if quality.tier == "weak":
            level = min(level, "low", key=VALID_LEVEL.index)
        elif quality.tier == "moderate":
            level = downgrade_level(level, 1)
        if mapping.confidence < CONF_COMPONENT:
            level = downgrade_level(level, 1)
        return level

    # -- detection block --------------------------------------------------- #
    def _build_detection(self, mapping: TelemetryMapping, artefacts: Artefacts, technique: Technique,
                         exclude: Iterable[str] = ()) -> tuple[dict[str, Any], list[str]]:
        """Assemble selections and the condition.

        Selections come in two kinds.  *Required* ones pin down what the event is
        about (the event type, the registry key written, the process accessed)
        and are AND-ed.  *Indicator* ones are alternative signs of malice (a
        suspicious flag, a known dumping tool) and are OR-ed.  Which kind a mined
        value becomes depends on the log source: ``rundll32.exe`` is the subject
        of a process-creation rule but only supporting evidence in a
        process-access rule whose subject is ``lsass.exe``.

        With nothing concrete at all the block is a skeleton: a ``selection_todo``
        that matches nothing until a person fills it in.
        """
        detection: dict[str, Any] = {}
        notes: list[str] = []
        required: list[str] = []
        indicators: list[str] = []
        roles = mapping.roles
        placed = place_artefacts(artefacts, mapping, exclude)
        object_first = (mapping.logsource.category or "").startswith(OBJECT_FIRST_CATEGORIES)

        def select(name: str, field_name: str, values: list[Any], bucket: list[str],
                   modifier: Optional[str] = None) -> None:
            key = f"{field_name}|{modifier}" if modifier else field_name
            detection[name] = {key: values}
            bucket.append(name)

        if mapping.base_selection:
            detection["selection_source"] = dict(mapping.base_selection)
            required.append("selection_source")

        subject_selected = False
        if roles.get("registry_key") and placed.registry_keys:
            select("selection_registry", roles["registry_key"], placed.registry_keys, required, "contains")
            subject_selected = True
        if roles.get("target_image") and placed.targets:
            select("selection_target", roles["target_image"], placed.targets, required, "endswith")
            subject_selected = True
        if roles.get("loaded_image") and placed.libraries:
            select("selection_loaded", roles["loaded_image"], placed.libraries, required, "endswith")
            subject_selected = True
        if roles.get("file") and placed.paths:
            if object_first:
                select("selection_path", roles["file"], placed.paths, required, "contains")
                subject_selected = True
            else:
                select("selection_indicator_path", roles["file"], placed.paths, indicators, "contains")

        if roles.get("image") and placed.actors:
            if not subject_selected:
                select("selection_image", roles["image"], placed.actors, required, "endswith")
            elif object_first:
                # Requiring reg.exe on a Run-key write would miss every write made
                # through the API - which is how most malware does it.
                notes.append(
                    f"ATT&CK also names {', '.join(a.lstrip('/').lstrip(chr(92)) for a in placed.actors[:4])}; "
                    "they were not required here because the change can be made by any process. "
                    "A companion process_creation rule is the place for them."
                )
            else:
                select("selection_indicator_source", roles["image"], placed.actors, indicators, "endswith")

        if roles.get("port") and placed.ports:
            if not subject_selected and "selection_image" not in detection:
                select("selection_port", roles["port"], placed.ports, required)
                subject_selected = True
            else:
                select("selection_indicator_port", roles["port"], placed.ports, indicators)

        content_field = roles.get("script") or roles.get("command_line")
        if content_field and placed.content:
            select("selection_indicator_content", content_field, placed.content, indicators, "contains")
        if roles.get("access_mask") and placed.access_masks:
            select("selection_indicator_access", roles["access_mask"], placed.access_masks, indicators)

        if not detection:
            detection["selection_todo"] = {self._todo_field(mapping): self.TODO_VALUE}
            detection["condition"] = "selection_todo"
            return detection, notes

        dropped = self._prune_generic_alternatives(detection, required, indicators)
        if dropped:
            notes.append(
                f"Left out {', '.join(dropped[:5])}: common in normal activity, and in a list of alternatives "
                "each value matches on its own. Add them back only together with a narrower condition."
            )

        condition_parts = list(required)
        if len(indicators) == 1:
            condition_parts.append(indicators[0])
        elif len(indicators) > 1:
            condition_parts.append("1 of selection_indicator_*")
        detection["condition"] = " and ".join(condition_parts)
        return detection, notes

    @staticmethod
    def _prune_generic_alternatives(detection: dict[str, Any], required: list[str],
                                    indicators: list[str]) -> list[str]:
        """Drop generic values from value lists they would make match on their own.

        Values in one list are alternatives, so ``[/etc/passwd, /bin/bash]``
        matches every event touching bash.  A generic value is harmless only when
        another part of the condition is specific: ``SourceImage: rundll32.exe`` is
        a signal once ``TargetImage: lsass.exe`` is required too.  Lists holding
        only generic values are kept - the rule is then graded weak, not hidden.
        """
        def specific(name: str) -> bool:
            return any(not is_generic(value) for value in selection_values(detection[name]))

        def prune(name: str) -> list[str]:
            removed: list[str] = []
            for key, values in detection[name].items():
                if isinstance(values, list) and any(is_generic(v) for v in values) and not all(is_generic(v) for v in values):
                    removed += [str(v) for v in values if is_generic(v)]
                    detection[name][key] = [v for v in values if not is_generic(v)]
            return removed

        behavioural_required = [name for name in required if name != "selection_source"]
        dropped: list[str] = []
        for name in indicators:
            if not any(specific(other) for other in behavioural_required):
                dropped += prune(name)
        for name in behavioural_required:
            anchored = any(specific(other) for other in behavioural_required if other != name) or (
                bool(indicators) and all(not any(is_generic(v) for v in selection_values(detection[i]))
                                         for i in indicators)
            )
            if not anchored:
                dropped += prune(name)
        return list(dict.fromkeys(dropped))

    @staticmethod
    def _todo_field(mapping: TelemetryMapping) -> str:
        roles = mapping.roles
        for role in ("command_line", "script", "image", "event_name", "file", "registry_key", "destination", "user"):
            if roles.get(role):
                return roles[role]
        return mapping.fields[0] if mapping.fields else "Message"

    # -- banner ------------------------------------------------------------ #
    def _artefact_counts(self, artefacts: Artefacts) -> dict[str, int]:
        return {
            name: len(values)
            for name, values in (
                ("executables", artefacts.executables),
                ("tools", artefacts.utilities),
                ("cmdlets", artefacts.cmdlets),
                ("registry keys", artefacts.registry_keys),
                ("paths", artefacts.paths),
                ("flags", artefacts.flags),
                ("api calls", artefacts.api_calls),
                ("access masks", artefacts.access_masks),
                ("ports", artefacts.ports),
            )
            if values
        }

    def _build_banner(self, rule: SigmaRule) -> list[str]:
        provenance = rule.provenance
        divider = "-" * 74
        heading = "SKELETON RULE - complete before use" if rule.quality.tier == "placeholder" else "DRAFT RULE"
        lines = [
            divider,
            f"{heading} - generated by sigma-generator v{__version__} on {rule.date}",
            divider,
            f"ATT&CK        : {provenance.technique_id} {provenance.technique_name}"
            + (f" (ATT&CK v{provenance.attack_version})" if provenance.attack_version else ""),
        ]
        if provenance.platform:
            lines.append(f"Platform      : {provenance.platform}")
        if provenance.strategy_id:
            lines.append(f"Strategy      : {provenance.strategy_id} {provenance.strategy_name}")
        if provenance.analytic_id:
            lines.append(f"Analytic      : {provenance.analytic_id}")
        lines.append(f"Telemetry     : {provenance.telemetry_source} -> {provenance.logsource_label}")
        lines.append(f"Quality       : {rule.quality.label} ({'; '.join(rule.quality.reasons)})")
        lines.append(f"Confidence    : {provenance.confidence:.2f} - {provenance.confidence_label}")
        if provenance.artefact_counts:
            summary = ", ".join(f"{count} {name}" for name, count in provenance.artefact_counts.items())
            lines.append(f"Mined content : {summary}")
        else:
            lines.append("Mined content : none - ATT&CK contained no field-level artefacts")
        if provenance.threat_label:
            lines.append(
                f"Threat context: {provenance.threat_label} - "
                f"{provenance.procedure_count} ATT&CK procedure example(s) mined first"
            )

        if provenance.mutable_elements:
            lines.append("")
            lines.append("ATT&CK tuning knobs for this analytic:")
            for name, description in provenance.mutable_elements:
                lines.append(f"  - {name}: {first_sentences(description, 1, 90)}")

        if provenance.notes:
            lines.append("")
            lines.append("Notes:")
            for note in provenance.notes:
                for index, chunk in enumerate(wrap_text(note, width=68).split("\n")):
                    lines.append(f"  - {chunk}" if index == 0 else f"    {chunk}")

        lines += [
            "",
            "Before deploying:",
            "  1. Check the field names against your own pipeline / field mappings.",
            "  2. Replace mined values with artefacts you have actually observed.",
            "  3. Add environment filters, then measure the false-positive rate.",
            "  4. Set `status: test` once validated, and re-issue the rule `id` if you fork it.",
            divider,
        ]
        return lines


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TAG_RE = re.compile(r"^[a-z0-9_\-]+\.[a-z0-9_\-\.]+$")


def validate_rule(rule: dict[str, Any]) -> list[str]:
    """Structural Sigma validation. Returns a list of human-readable errors."""
    errors: list[str] = []
    if not isinstance(rule, dict):
        return ["rule is not a YAML mapping"]

    for required in ("title", "logsource", "detection"):
        if not rule.get(required):
            errors.append(f"missing required field: {required}")

    title = rule.get("title")
    if isinstance(title, str):
        if len(title) > 256:
            errors.append("title exceeds the 256 character limit")
        if title.endswith("."):
            errors.append("title should not end with a period")
    elif title is not None:
        errors.append("title must be a string")

    rule_id = rule.get("id")
    if rule_id is not None and not (isinstance(rule_id, str) and _UUID_RE.match(rule_id)):
        errors.append("id must be a UUID")

    status = rule.get("status")
    if status is not None and status not in VALID_STATUS:
        errors.append(f"status '{status}' is not one of {', '.join(VALID_STATUS)}")

    level = rule.get("level")
    if level is not None and level not in VALID_LEVEL:
        errors.append(f"level '{level}' is not one of {', '.join(VALID_LEVEL)}")

    date_value = rule.get("date")
    if date_value is not None and not _DATE_RE.match(str(date_value)):
        errors.append("date must be formatted YYYY-MM-DD")

    logsource = rule.get("logsource")
    if isinstance(logsource, dict):
        if not any(logsource.get(key) for key in ("category", "product", "service")):
            errors.append("logsource needs at least one of category, product or service")
        unknown = set(logsource) - {"category", "product", "service", "definition"}
        if unknown:
            errors.append(f"logsource has unsupported key(s): {', '.join(sorted(unknown))}")
    elif logsource is not None:
        errors.append("logsource must be a mapping")

    for tag in rule.get("tags") or []:
        if not isinstance(tag, str) or not _TAG_RE.match(tag):
            errors.append(f"tag '{tag}' is not in namespace.value form")

    errors.extend(_validate_detection(rule.get("detection")))
    return errors


def _validate_detection(detection: Any) -> list[str]:
    if detection is None:
        return []
    if not isinstance(detection, dict):
        return ["detection must be a mapping"]

    errors: list[str] = []
    condition = detection.get("condition")
    identifiers = [key for key in detection if key not in ("condition", "timeframe")]
    if not identifiers:
        errors.append("detection has no search identifiers")
    if not condition:
        errors.append("detection is missing a condition")
        return errors
    if isinstance(condition, list):
        conditions = [str(item) for item in condition]
    else:
        conditions = [str(condition)]

    for expression in conditions:
        for token in _TOKEN_RE.findall(expression):
            if token.lower() in _CONDITION_KEYWORDS:
                continue
            if token.endswith("*"):
                prefix = token[:-1]
                if not any(identifier.startswith(prefix) for identifier in identifiers):
                    errors.append(f"condition references '{token}' but no selection matches it")
            elif token not in identifiers:
                errors.append(f"condition references undefined selection '{token}'")

    for name in identifiers:
        value = detection[name]
        if isinstance(value, dict) and not value:
            errors.append(f"selection '{name}' is empty")
        elif isinstance(value, list) and not value:
            errors.append(f"selection '{name}' is empty")
    return errors


def validate_with_pysigma(rule_yaml: str) -> tuple[bool, list[str]]:
    """Parse the rule with pySigma when it is installed.

    Returns ``(ran, errors)`` so callers can tell "no errors" from "not checked".
    """
    try:
        from sigma.collection import SigmaCollection  # type: ignore
    except ImportError:
        return False, []
    try:
        collection = SigmaCollection.from_yaml(rule_yaml)
        # Correlation rules reference their base rules by name; make pySigma prove
        # every reference resolves.
        collection.resolve_rule_references()
    except Exception as exc:  # pySigma raises a family of SigmaError subclasses
        return True, [f"pySigma: {exc}"]
    return True, []


VALID_CORRELATION_TYPES = (
    "event_count", "value_count", "temporal", "temporal_ordered", "value_sum", "value_avg", "value_percentile",
)
_COUNTING_CORRELATIONS = ("event_count", "value_count", "value_sum", "value_avg", "value_percentile")
_FIELD_CORRELATIONS = ("value_count", "value_sum", "value_avg", "value_percentile")
_TIMESPAN_RE = re.compile(r"^\d+[smhd]$")
_CONDITION_OPERATORS = {"gt", "gte", "lt", "lte", "eq", "neq"}


def validate_correlation(rule: dict[str, Any], known_rules: Iterable[str] = ()) -> list[str]:
    """Structural checks for a Sigma correlation rule (spec v2.1)."""
    errors: list[str] = []
    if not rule.get("title"):
        errors.append("missing required field: title")
    rule_id = rule.get("id")
    if rule_id is not None and not (isinstance(rule_id, str) and _UUID_RE.match(rule_id)):
        errors.append("id must be a UUID")
    if rule.get("status") is not None and rule["status"] not in VALID_STATUS:
        errors.append(f"status '{rule['status']}' is not one of {', '.join(VALID_STATUS)}")
    if rule.get("level") is not None and rule["level"] not in VALID_LEVEL:
        errors.append(f"level '{rule['level']}' is not one of {', '.join(VALID_LEVEL)}")

    correlation = rule.get("correlation")
    if not isinstance(correlation, dict):
        return errors + ["correlation must be a mapping"]

    kind = correlation.get("type")
    if kind not in VALID_CORRELATION_TYPES:
        errors.append(f"correlation type '{kind}' is not one of {', '.join(VALID_CORRELATION_TYPES)}")

    referenced = correlation.get("rules")
    known = set(known_rules)
    if not isinstance(referenced, list) or not referenced:
        errors.append("correlation.rules must list at least one rule")
    else:
        for reference in referenced:
            reference = str(reference)
            # UUID references may point at rules that live in other files.
            if reference not in known and not _UUID_RE.match(reference):
                errors.append(f"correlation references rule '{reference}', which is not defined in this file")
        if kind in ("temporal", "temporal_ordered") and len(referenced) < 2:
            errors.append(f"a {kind} correlation needs at least two rules")

    group_by = correlation.get("group-by")
    if not isinstance(group_by, list) or not group_by:
        errors.append("correlation.group-by must list at least one field")

    if not _TIMESPAN_RE.match(str(correlation.get("timespan", ""))):
        errors.append("correlation.timespan must look like 30s, 10m, 1h or 1d")

    aliases = correlation.get("aliases")
    if aliases is not None:
        if not isinstance(aliases, dict):
            errors.append("correlation.aliases must be a mapping")
        else:
            for alias, per_rule in aliases.items():
                if not isinstance(per_rule, dict):
                    errors.append(f"alias '{alias}' must map rule names to field names")
                    continue
                for rule_name in per_rule:
                    if rule_name not in known:
                        errors.append(f"alias '{alias}' refers to unknown rule '{rule_name}'")

    condition = correlation.get("condition")
    if kind in _COUNTING_CORRELATIONS:
        if not isinstance(condition, dict) or not (_CONDITION_OPERATORS & set(condition)):
            errors.append(f"a {kind} correlation needs a condition such as `gte: 10`")
        elif kind in _FIELD_CORRELATIONS and not condition.get("field"):
            errors.append(f"a {kind} correlation needs `field` in its condition")
    return errors


def validate_sigma_text(text: str) -> list[str]:
    """Validate a Sigma file: a single rule, or a multi-document correlation file."""
    try:
        documents = [doc for doc in load_all_yaml(text) if doc is not None]
    except Exception as exc:  # yaml.YAMLError and friends
        return [f"not valid YAML: {exc}"]
    if not documents:
        return ["file contains no YAML documents"]

    names = [doc.get("name") for doc in documents if isinstance(doc, dict) and doc.get("name")]
    known = set(names) | {doc.get("id") for doc in documents if isinstance(doc, dict) and doc.get("id")}
    errors: list[str] = []
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        errors.append(f"rule names must be unique within a file: {', '.join(duplicates)}")

    multi = len(documents) > 1
    for number, document in enumerate(documents, start=1):
        if isinstance(document, dict) and "correlation" in document:
            problems = validate_correlation(document, known)
        else:
            problems = validate_rule(document)
        prefix = f"document {number}: " if multi else ""
        errors.extend(prefix + problem for problem in problems)
    return errors
