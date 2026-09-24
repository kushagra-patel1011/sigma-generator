"""Shared helpers: configuration, logging, text normalisation and YAML rendering.

Nothing in here knows about Sigma or ATT&CK semantics - it is the plumbing the
rest of the package sits on.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import sys
import textwrap
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output"
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

LOG = logging.getLogger("sigma_generator")


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class SigmaGeneratorError(Exception):
    """Base class for every error this tool raises on purpose."""


class DataUnavailableError(SigmaGeneratorError):
    """The ATT&CK dataset could not be loaded or downloaded."""


class TechniqueNotFoundError(SigmaGeneratorError):
    """The requested ATT&CK technique ID does not exist in the dataset."""


class UnmappableTechniqueError(SigmaGeneratorError):
    """ATT&CK describes no telemetry this tool can express as a Sigma logsource."""


class ThreatNotFoundError(SigmaGeneratorError):
    """The requested ATT&CK group, software or campaign does not exist."""


class FullyCoveredError(SigmaGeneratorError):
    """--gaps-only was requested, but SigmaHQ already watches every recommended log source."""


class InsufficientEvidenceError(SigmaGeneratorError):
    """ATT&CK names telemetry for the technique but no concrete values to detect on."""


# --------------------------------------------------------------------------- #
# Environment / logging
# --------------------------------------------------------------------------- #
def load_env(path: str | os.PathLike[str] | None = None, override: bool = False) -> dict[str, str]:
    """Load a ``KEY=value`` .env file into ``os.environ``.

    Deliberately dependency-free: the supported format is the documented subset
    in ``.env.example`` (comments, blank lines, optional ``export`` prefix and
    optional surrounding quotes).
    """
    env_path = Path(path) if path else PROJECT_ROOT / ".env"
    loaded: dict[str, str] = {}
    if not env_path.is_file():
        return loaded

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        loaded[key] = value
        if override or key not in os.environ:
            os.environ[key] = value
    LOG.debug("Loaded %d value(s) from %s", len(loaded), env_path)
    return loaded


def env_str(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, TypeError, ValueError):
        return default


def setup_logging(verbosity: int = 0, quiet: bool = False) -> None:
    """Configure the package logger. ``-v`` -> INFO, ``-vv`` -> DEBUG."""
    if quiet:
        level = logging.ERROR
    elif verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
    LOG.handlers.clear()
    LOG.addHandler(handler)
    LOG.setLevel(level)
    LOG.propagate = False


# --------------------------------------------------------------------------- #
# Filesystem helpers
# --------------------------------------------------------------------------- #
def ensure_dir(path: str | os.PathLike[str]) -> Path:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write_text(path: str | os.PathLike[str], content: str) -> Path:
    """Write UTF-8 text with LF endings, creating parent directories."""
    target = Path(path)
    ensure_dir(target.parent)
    if not content.endswith("\n"):
        content += "\n"
    # open() rather than Path.write_text(newline=...), which needs Python 3.10.
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    return target


def sha256_file(path: str | os.PathLike[str], chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def format_bytes(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def utcnow_iso() -> str:
    """STIX-style timestamp: millisecond precision, explicit ``Z``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def today_iso() -> str:
    return date.today().isoformat()


def slugify(text: str, max_length: int = 60) -> str:
    """Filename-safe, lowercase, underscore-separated slug."""
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()
    slug = re.sub(r"_+", "_", slug)
    return slug[:max_length].strip("_") or "rule"


# --------------------------------------------------------------------------- #
# ATT&CK text normalisation
# --------------------------------------------------------------------------- #
_CITATION_RE = re.compile(r"\s*\(Citation:[^)]*\)")
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_CODE_TAG_RE = re.compile(r"</?code>")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t]+")


def clean_text(text: str | None) -> str:
    """Strip ATT&CK markup (citations, markdown links, ``<code>`` spans)."""
    if not text:
        return ""
    cleaned = _CITATION_RE.sub("", text)
    cleaned = _MD_LINK_RE.sub(r"\1", cleaned)
    cleaned = _CODE_TAG_RE.sub("", cleaned)
    cleaned = _HTML_TAG_RE.sub("", cleaned)
    cleaned = cleaned.replace("\r\n", "\n")
    for entity, char in (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'")):
        cleaned = cleaned.replace(entity, char)
    cleaned = _WS_RE.sub(" ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9(])")
_ABBREVIATIONS = ("i.e.", "e.g.", "etc.", "vs.", "cf.", "approx.", "incl.", "inc.", "ltd.", "corp.", "no.", "al.")


def split_sentences(text: str) -> list[str]:
    """Sentence split that does not break on ``i.e.`` / ``e.g.`` style abbreviations."""
    sentences: list[str] = []
    for part in _SENTENCE_END.split(text):
        if sentences and sentences[-1].rstrip().lower().endswith(_ABBREVIATIONS):
            sentences[-1] = f"{sentences[-1]} {part}"
        else:
            sentences.append(part)
    return sentences


def first_sentences(text: str, count: int = 2, max_chars: int = 500) -> str:
    """First ``count`` sentences of ``text``, hard-capped at ``max_chars``."""
    cleaned = clean_text(text).replace("\n", " ")
    if not cleaned:
        return ""
    sentences = split_sentences(cleaned)
    summary = " ".join(sentences[:count]).strip()
    if len(summary) > max_chars:
        summary = summary[:max_chars].rsplit(" ", 1)[0].rstrip(",;:") + "..."
    return summary


def wrap_text(text: str, width: int = 96) -> str:
    """Soft-wrap a paragraph so YAML block scalars stay readable."""
    paragraphs = [p.strip() for p in text.split("\n") if p.strip()]
    return "\n".join("\n".join(textwrap.wrap(p, width=width)) or p for p in paragraphs)


# --------------------------------------------------------------------------- #
# Artefact extraction
# --------------------------------------------------------------------------- #
_EXE_RE = re.compile(
    r"\b([A-Za-z0-9][A-Za-z0-9_\-\.]{1,40}\."
    r"(?:exe|dll|sys|ps1|psm1|vbs|vbe|js|jse|bat|cmd|hta|scr|com|py|sh|elf|so|dylib|jar|msi|lnk))\b",
    re.IGNORECASE,
)
_CMDLET_RE = re.compile(
    r"\b((?:Get|Set|New|Add|Remove|Invoke|Start|Stop|Enable|Disable|Export|Import|Copy|Move"
    r"|Register|Unregister|Update|Install|Uninstall|Convert|Out|Write|Test)-[A-Z][A-Za-z0-9]{2,30})\b"
)
_REGISTRY_RE = re.compile(
    r"\b((?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)(?:\\[A-Za-z0-9 _\-\.\*]+){1,10})",
    re.IGNORECASE,
)
_WIN_PATH_RE = re.compile(
    r"(?<![\w\\])((?:[A-Za-z]:\\|\\\\|%[A-Za-z]+%\\)[A-Za-z0-9 _\-\.\\\*]{3,80})"
)
_NIX_PATH_RE = re.compile(
    r"(?<![\w/])((?:/etc|/var|/usr|/tmp|/opt|/bin|/sbin|/dev|/proc|/Library|/System|/Users)"
    r"(?:/[A-Za-z0-9_\-\.\*]+){1,8}/?)"
)
_FLAG_RE = re.compile(r"(?<![\w\-])(-{1,2}[A-Za-z][A-Za-z0-9\-]{1,20})\b")
_API_RE = re.compile(r"\b((?:[A-Z][a-z0-9]+){2,5}(?:Ex|A|W)?)\(")
_ACCESS_MASK_RE = re.compile(r"\b(0x[0-9A-Fa-f]{3,8})\b")

DATA_DIR = Path(__file__).resolve().parent / "data"


def _load_tool_lexicon() -> dict[str, Any]:
    """Read ``data/tools.yml`` - the curated vocabulary of tool names."""
    path = DATA_DIR / "tools.yml"
    try:
        lexicon = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:  # pragma: no cover - packaging error
        raise SigmaGeneratorError(f"Cannot read the tool lexicon {path}: {exc}") from exc
    contextual = lexicon.get("contextual") or {}
    return {
        "windows": {str(t).lower() for t in lexicon.get("windows") or []},
        "unix": {str(t).lower() for t in lexicon.get("unix") or []},
        "both": {str(t).lower() for t in lexicon.get("both") or []},
        "contextual_windows": {str(k).lower(): [str(a) for a in v] for k, v in (contextual.get("windows") or {}).items()},
        "contextual_unix": {str(k).lower(): [str(a) for a in v] for k, v in (contextual.get("unix") or {}).items()},
        "windows_system_files": {str(t).lower() for t in lexicon.get("windows_system_files") or []},
    }


_LEXICON = _load_tool_lexicon()

#: Tool names recognised per OS family (a name in both sets exists on both).
WINDOWS_UTILITIES = frozenset(_LEXICON["windows"] | _LEXICON["both"] | set(_LEXICON["contextual_windows"]))
NIX_UTILITIES = frozenset(_LEXICON["unix"] | _LEXICON["both"] | set(_LEXICON["contextual_unix"]))
#: Files Windows ships, which attacks use rather than create (comsvcs.dll).
WINDOWS_SYSTEM_FILES = frozenset(_LEXICON["windows_system_files"])

_PLAIN_TOOLS = sorted(_LEXICON["windows"] | _LEXICON["unix"] | _LEXICON["both"], key=len, reverse=True)
_UTILITY_RE = re.compile(
    r"(?<![\w\-./\\])(" + "|".join(re.escape(t) for t in _PLAIN_TOOLS) + r")(?:\.exe)?(?![\w\-])",
    re.IGNORECASE,
)


def _contextual_pattern(name: str, arguments: Sequence[str]) -> "re.Pattern[str]":
    alternatives = "|".join(
        re.escape(argument) + (r"(?![\w\-])" if argument[-1:].isalnum() else "") for argument in arguments
    )
    return re.compile(rf"(?<![\w\-./\\])({re.escape(name)})(?:\.exe)?\s+(?:{alternatives})", re.IGNORECASE)


#: Short or ambiguous names ("reg", "security", "defaults") only count when followed
#: by one of their real sub-commands: "reg add", "security dump-keychain".
_CONTEXTUAL_RES = [
    _contextual_pattern(name, arguments)
    for family in ("contextual_windows", "contextual_unix")
    for name, arguments in _LEXICON[family].items()
]

_PORT_RE = re.compile(
    r"\b(?:ports?|tcp|udp)\s*(?:[:=/#]\s*)?(\d{1,5}(?:\s*(?:/|,|and|or|&)\s*(?:ports?\s*)?\d{1,5})*)",
    re.IGNORECASE,
)


def _ports(text: str) -> list[int]:
    ports: list[int] = []
    for group in _PORT_RE.findall(text):
        for number in re.findall(r"\d{1,5}", group):
            value = int(number)
            if 0 < value <= 65535 and value not in ports:
                ports.append(value)
    return ports

# Tokens the regexes above pick up that are never useful as detection content.
_ARTEFACT_STOPWORDS = {
    "e.g", "i.e", "etc", "example.exe", "malware.exe", "file.exe", "program.exe",
    "payload.exe", "evil.exe", "binary.exe", "application.exe", "installer.exe",
    "-the", "-and", "-or", "-in", "-of", "-to", "-for", "-is", "-as", "-based",
    "-like", "-level", "-line", "-time", "-side", "-party", "-specific", "-related",
    "-only", "-user", "-day", "-known", "-defined", "-made", "-on", "-off", "-up",
    "-out", "-by", "-with", "-from", "-into", "-over", "-driven", "-world", "-case",
    "-party", "-scale", "-value", "-name", "-code", "-data", "-list", "-set",
}


@dataclass
class Artefacts:
    """Detection-relevant strings mined out of ATT&CK prose."""

    executables: list[str] = field(default_factory=list)
    utilities: list[str] = field(default_factory=list)
    cmdlets: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    api_calls: list[str] = field(default_factory=list)
    access_masks: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)

    def _groups(self) -> tuple[list[Any], ...]:
        return (
            self.executables, self.utilities, self.cmdlets, self.registry_keys,
            self.paths, self.flags, self.api_calls, self.access_masks, self.ports,
        )

    def merged_with(self, other: "Artefacts", limit: int = 10) -> "Artefacts":
        """This object's values first, then ``other``'s, de-duplicated and capped."""
        def merge(first: list[Any], second: list[Any]) -> list[Any]:
            seen: dict[str, Any] = {}
            for value in list(first) + list(second):
                seen.setdefault(str(value).lower(), value)
            return list(seen.values())[:limit]

        return Artefacts(**{
            name: merge(getattr(self, name), getattr(other, name))
            for name in ("executables", "utilities", "cmdlets", "registry_keys", "paths",
                         "flags", "api_calls", "access_masks", "ports")
        })

    def __bool__(self) -> bool:
        return any(self._groups())

    @property
    def count(self) -> int:
        return sum(len(group) for group in self._groups())


# Prose words that get swept up when a path or registry key is followed by text
# such as "HKLM\...\Run and the startup folder".
_TRAILING_PROSE = {
    "a", "an", "and", "are", "as", "at", "be", "been", "but", "by", "can", "for",
    "from", "had", "has", "have", "if", "in", "is", "it", "its", "may", "of", "on",
    "or", "such", "that", "the", "then", "these", "this", "those", "to", "using",
    "was", "were", "when", "where", "which", "while", "will", "with",
}


_ENDS_WITH_FILE_RE = re.compile(r"\.[A-Za-z0-9]{2,4}$")


def _trim_trailing_prose(value: str) -> str:
    """Drop the English prose a greedy path/registry match dragged in.

    Real path and key segments are capitalised ("User Shell Folders"), while the
    sentence that follows one in ATT&CK prose continues in lower case
    ("...\\RunOnceEx is also available but..."), so the first lower-case word
    after a space marks where the artefact ended.
    """
    parts = value.split(" ")
    kept = [parts[0]]
    for part in parts[1:]:
        # Lower-case prose follows, or the previous part already ended in a file
        # name ("...\comsvcs.dll MiniDump PID" is a command, not a path).
        if part[:1].islower() or _ENDS_WITH_FILE_RE.search(kept[-1]):
            break
        kept.append(part)
    while len(kept) > 1 and kept[-1].lower().strip(".,;:") in _TRAILING_PROSE:
        kept.pop()
    return " ".join(kept).rstrip(" .,;:")


#: File stems ATT&CK uses for illustrative names ("example.dll", "file.exe").
_PLACEHOLDER_STEMS = {
    "example", "exampledll", "file", "malware", "malicious", "evil", "payload", "program",
    "binary", "application", "installer", "sample", "test", "foo", "bar", "library",
    "dll", "exe", "script", "name", "filename", "something", "arbitrary",
}


#: Path segments that mark an illustrative path ("C:\temp\evil.exe").
_PLACEHOLDER_SEGMENTS = {"evil", "malicious", "malware", "payload", "example", "attacker", "badfile", "foo", "bar"}


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if lowered in _ARTEFACT_STOPWORDS:
        return True
    stem, dot, extension = lowered.rpartition(".")
    if dot and 1 <= len(extension) <= 5 and stem in _PLACEHOLDER_STEMS:
        return True
    if "\\" in lowered or "/" in lowered:
        segments = re.split(r"[\\/]+", lowered)
        return any(segment.split(".", 1)[0] in _PLACEHOLDER_SEGMENTS for segment in segments if segment)
    return False


def _dedupe(values: Iterable[str], limit: int, lower: bool = False) -> list[str]:
    seen: dict[str, str] = {}
    for value in values:
        value = value.strip().strip(".,;:'\"()[]")
        if not value or _is_placeholder(value):
            continue
        key = value.lower()
        if key not in seen:
            seen[key] = key if lower else value
        if len(seen) >= limit:
            break
    return sorted(seen.values())


def extract_artefacts(*texts: str, limit: int = 10) -> Artefacts:
    """Mine executables, utilities, cmdlets, registry keys, paths and flags.

    The output is *candidate* detection content: these strings come from prose,
    not from telemetry, which is why every generated rule carries a review
    banner and ships as ``status: experimental``.
    """
    blob = "\n".join(t for t in texts if t)
    if not blob:
        return Artefacts()

    # Quoted spans are the highest-signal source for command-line flags.
    quoted = re.findall(r"[`'\"]([^`'\"\n]{2,60})[`'\"]", blob)
    quoted_blob = "\n".join(quoted)
    flags = [flag for flag in _FLAG_RE.findall(quoted_blob) if len(flag) > 2]

    tools = [match.lower() for match in _UTILITY_RE.findall(blob)]
    for pattern in _CONTEXTUAL_RES:
        tools.extend(match.lower() for match in pattern.findall(blob))

    return Artefacts(
        executables=_dedupe(_EXE_RE.findall(blob), limit, lower=True),
        utilities=_dedupe(tools, limit, lower=True),
        cmdlets=_dedupe(_CMDLET_RE.findall(blob), limit),
        registry_keys=_dedupe((_trim_trailing_prose(m) for m in _REGISTRY_RE.findall(blob)), limit),
        paths=_dedupe(
            (_trim_trailing_prose(m) for m in _WIN_PATH_RE.findall(blob) + _NIX_PATH_RE.findall(blob)),
            limit,
        ),
        flags=_dedupe(flags, limit, lower=True),
        api_calls=_dedupe(_API_RE.findall(blob), limit),
        access_masks=_dedupe(_ACCESS_MASK_RE.findall(blob), limit, lower=True),
        ports=_ports(blob)[:limit],
    )


# --------------------------------------------------------------------------- #
# Normalising mined values into what telemetry actually records
# --------------------------------------------------------------------------- #
_HIVE_RE = re.compile(
    r"^(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG"
    r"|HKLM|HKCU|HKCR|HKU|HKCC)(?=\\)",
    re.IGNORECASE,
)


def normalise_registry_key(key: str) -> str:
    r"""Make a registry path match however the sensor spells the hive.

    Prose says ``HKEY_CURRENT_USER\Software\...``; Sysmon records
    ``HKU\S-1-5-21-...\Software\...`` and Security 4657 records
    ``\REGISTRY\USER\...``.  Dropping the hive and matching with ``|contains``
    covers all three.
    """
    return _HIVE_RE.sub("", key.strip())


#: Environment variables as they appear in prose -> what a path looks like in
#: telemetry, where the variable has already been expanded.
_ENV_PATHS = {
    "%appdata%": "\\AppData\\Roaming",
    "%localappdata%": "\\AppData\\Local",
    "%temp%": "\\Temp",
    "%tmp%": "\\Temp",
    "%public%": "\\Users\\Public",
    "%programdata%": ":\\ProgramData",
    "%windir%": ":\\Windows",
    "%systemroot%": ":\\Windows",
    "%programfiles%": ":\\Program Files",
    "%programfiles(x86)%": ":\\Program Files (x86)",
    "%systemdrive%": ":",
    "%userprofile%": "",
    "%homepath%": "",
}
_ENV_VAR_RE = re.compile(r"^%[A-Za-z0-9_()]+%", re.IGNORECASE)
_DRIVE_RE = re.compile(r"^[A-Za-z]:\\")


def normalise_windows_path(path: str) -> str:
    r"""Turn a prose path into a value that matches expanded telemetry.

    ``%APPDATA%\Microsoft`` -> ``\AppData\Roaming\Microsoft`` and
    ``C:\Windows\Temp`` -> ``:\Windows\Temp`` (the drive letter varies).
    Non-Windows paths are returned unchanged.
    """
    value = path.strip()
    match = _ENV_VAR_RE.match(value)
    if match:
        replacement = _ENV_PATHS.get(match.group(0).lower(), "")
        value = replacement + value[match.end():]
    elif _DRIVE_RE.match(value):
        value = value[1:]
    return value


def minimise_contains(values: Iterable[str]) -> list[str]:
    """Drop values another value already covers under ``|contains`` matching.

    ``\\CurrentVersion\\Run`` matches everything ``\\CurrentVersion\\RunOnce``
    does, so listing both only adds noise.  Comparison is case-insensitive like
    Sigma's default string matching.
    """
    unique: dict[str, str] = {}
    for value in values:
        if value and value.lower() not in unique:
            unique[value.lower()] = value
    kept = [
        original for lowered, original in unique.items()
        if not any(other != lowered and other in lowered for other in unique)
    ]
    return sorted(kept, key=str.lower)


# --------------------------------------------------------------------------- #
# YAML rendering (SigmaHQ house style)
# --------------------------------------------------------------------------- #
class LiteralScalar(str):
    """Marker type forcing a ``|`` block scalar in the rendered YAML."""


class _SigmaDumper(yaml.SafeDumper):
    """SafeDumper that indents sequences under their parent key, like SigmaHQ."""

    def increase_indent(self, flow: bool = False, indentless: bool = False):
        return super().increase_indent(flow, False)

    def ignore_aliases(self, data: Any) -> bool:
        return True


def _literal_representer(dumper: yaml.Dumper, data: LiteralScalar):
    text = "\n".join(line.rstrip() for line in str(data).splitlines())
    return dumper.represent_scalar("tag:yaml.org,2002:str", text + "\n", style="|")


def _str_representer(dumper: yaml.Dumper, data: str):
    if "\n" in data:
        return _literal_representer(dumper, LiteralScalar(data))
    # Single-quote anything a Sigma backend would rather see quoted.
    if "\\" in data or data != data.strip() or data[:1] in ("*", "?", "@", "`", "%", "&", "!"):
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="'")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_SigmaDumper.add_representer(LiteralScalar, _literal_representer)
_SigmaDumper.add_representer(str, _str_representer)

# SigmaHQ writes `date: 2023-09-18` unquoted.  PyYAML would quote our date
# strings to stop them resolving to a timestamp, so drop that implicit resolver
# from this dumper only.
_SigmaDumper.yaml_implicit_resolvers = {
    first_char: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for first_char, resolvers in yaml.SafeDumper.yaml_implicit_resolvers.items()
}


def dump_yaml(data: Any, width: int = 4096) -> str:
    """Render ``data`` as YAML using SigmaHQ formatting conventions."""
    return yaml.dump(
        data,
        Dumper=_SigmaDumper,
        sort_keys=False,
        default_flow_style=False,
        indent=4,
        allow_unicode=True,
        width=width,
    )


def load_yaml(text: str) -> Any:
    return yaml.safe_load(text)


def load_all_yaml(text: str) -> list[Any]:
    """All documents of a multi-document YAML stream (``---`` separated)."""
    return list(yaml.safe_load_all(text))


def comment_block(lines: Sequence[str], prefix: str = "# ") -> str:
    """Render ``lines`` as a YAML comment block."""
    return "\n".join(f"{prefix}{line}".rstrip() if line else prefix.rstrip() for line in lines)
