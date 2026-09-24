"""Local web interface for sigma-generator - Python standard library only.

    python -m src.main ui

Serves a single-page app plus a small JSON API on http://127.0.0.1:8765.
Everything runs on this computer; the page loads nothing from the Internet.

Hardening, because this is a security tool that writes files:

* binds to 127.0.0.1 unless told otherwise, and warns loudly if not;
* rejects requests whose ``Host`` header is not this server (DNS rebinding);
* state-changing requests must be ``POST`` with ``Content-Type: application/json``
  and an ``X-Requested-With`` header, which a cross-site form or ``fetch`` without
  CORS cannot send (CSRF);
* request bodies are capped, and every JSON field is type-checked;
* responses carry a strict Content-Security-Policy and ``nosniff`` headers;
* only three known static files can be served - no path is taken from the URL.
"""

from __future__ import annotations

import io
import ipaddress
import json
import re
import threading
import webbrowser
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, unquote, urlparse

from .. import __version__
from ..attack_fetcher import THREAT_KINDS
from ..packs import render_pack_files, write_pack
from ..service import GenerateOptions, TechniqueResult, Workspace
from ..sigma_generator import VALID_LEVEL, VALID_STATUS, validate_with_pysigma
from ..sigmahq import default_index_path, download_index
from ..stix_builder import VALID_TLP, dump_bundle
from ..utils import DEFAULT_OUTPUT_DIR, LOG, PROJECT_ROOT, SigmaGeneratorError, slugify, write_text

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
MAX_BODY_BYTES = 64 * 1024
#: How much of an oversized body is read and discarded before the error response.
MAX_DRAIN_BYTES = 1024 * 1024
REQUIRED_HEADER = "X-Requested-With"
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


# --------------------------------------------------------------------------- #
# Request parsing helpers
# --------------------------------------------------------------------------- #
def _bool(body: dict[str, Any], key: str) -> bool:
    value = body.get(key, False)
    if not isinstance(value, bool):
        raise ApiError(HTTPStatus.BAD_REQUEST, f"'{key}' must be true or false")
    return value


def _text(body: dict[str, Any], key: str, max_length: int = 120,
          choices: Optional[tuple[str, ...]] = None) -> Optional[str]:
    value = body.get(key)
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > max_length:
        raise ApiError(HTTPStatus.BAD_REQUEST, f"'{key}' must be a string of at most {max_length} characters")
    value = value.strip()
    if choices is not None and value not in choices:
        raise ApiError(HTTPStatus.BAD_REQUEST, f"'{key}' must be one of: {', '.join(choices)}")
    return value


def _options_from(body: dict[str, Any]) -> GenerateOptions:
    return GenerateOptions(
        platform=_text(body, "platform", 40),
        analytic=_text(body, "analytic", 12),
        all_analytics=_bool(body, "all_analytics"),
        chains=_bool(body, "chains"),
        gaps_only=_bool(body, "gaps_only"),
        with_campaigns=_bool(body, "with_campaigns"),
        author=_text(body, "author", 120),
        status=_text(body, "status", 20, VALID_STATUS),
        level=_text(body, "level", 20, VALID_LEVEL),
        tlp=_text(body, "tlp", 10, VALID_TLP),
        deterministic=_bool(body, "deterministic"),
        keep_revoked=_bool(body, "keep_revoked"),
        include_skeletons=_bool(body, "include_skeletons"),
    )


def _matches(detection: dict[str, Any]) -> list[dict[str, Any]]:
    """A detection block as readable rows: the field, the values it looks for,
    and whether it is required or one of several alternative signs."""
    condition = str(detection.get("condition", ""))
    any_of = "1 of selection_indicator_*" in condition
    rows: list[dict[str, Any]] = []
    for name, block in detection.items():
        if name == "condition" or not isinstance(block, dict):
            continue
        for field, value in block.items():
            values = value if isinstance(value, list) else [value]
            rows.append({
                "field": field,
                "values": [str(v) for v in values[:8]],
                "more": max(0, len(values) - 8),
                "optional": any_of and name.startswith("selection_indicator"),
                "event": name == "selection_source",
            })
    return rows


def _rule_payload(rule: Any, include_banner: bool, problems: list[str]) -> dict[str, Any]:
    is_chain = hasattr(rule, "correlation")
    text = rule.to_yaml(include_banner=include_banner)
    ran, pysigma_problems = validate_with_pysigma(rule.to_yaml(include_banner=False))
    payload = {
        "kind": "chain" if is_chain else "rule",
        "id": rule.id,
        "title": rule.title,
        "filename": rule.filename(),
        "level": rule.level,
        "logsource": rule.provenance.logsource_label,
        "telemetry": rule.provenance.telemetry_source,
        "confidence": rule.provenance.confidence,
        "quality": {"tier": rule.quality.tier, "meaning": rule.quality.meaning,
                    "reasons": list(rule.quality.reasons)},
        "platform": rule.provenance.platform,
        "analytic": rule.provenance.analytic_id,
        "notes": list(rule.provenance.notes),
        "yaml": text,
        "problems": problems + pysigma_problems,
        "pysigma_checked": ran,
    }
    if not is_chain:
        payload["matches"] = _matches(rule.detection)
    if is_chain:
        payload["steps"] = [{"name": s.name, "logsource": s.logsource_label, "telemetry": s.telemetry_source,
                             "quality": s.quality.tier, "matches": _matches(s.detection)} for s in rule.steps]
        payload["timespan"] = rule.correlation["timespan"]
        payload["group_by"] = rule.correlation["group-by"]
        payload["correlation_kind"] = rule.kind
        payload["correlation_type"] = rule.correlation["type"]
        payload["condition"] = rule.correlation.get("condition")
    return payload


def _object_counts(bundle: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for obj in bundle.get("objects", []):
        counts[obj["type"]] = counts.get(obj["type"], 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Application
# --------------------------------------------------------------------------- #
class WebApp:
    """Route handlers.  Kept separate from the HTTP plumbing so tests can call them."""

    def __init__(self, workspace: Workspace, output_root: Optional[Path] = None) -> None:
        self.workspace = workspace
        self.output_root = output_root or DEFAULT_OUTPUT_DIR
        self._lock = threading.Lock()   # dataset loading and SigmaHQ downloads are not re-entrant

    # -- GET ------------------------------------------------------------------ #
    def status(self, _query: dict[str, list[str]]) -> dict[str, Any]:
        with self._lock:
            dataset = self.workspace.dataset
            index = self.workspace.coverage_index(required=False)
        return {
            "version": __version__,
            "attack": {"version": dataset.version, "techniques": len(dataset.technique_ids())},
            "sigmahq": {
                "available": index is not None,
                "release": index.release if index else None,
                "rules": len(index.rules) if index else 0,
            },
            "offline": self.workspace.offline,
            "choices": {"levels": list(VALID_LEVEL), "statuses": list(VALID_STATUS), "tlp": list(VALID_TLP)},
        }

    def search(self, query: dict[str, list[str]]) -> dict[str, Any]:
        text = (query.get("q") or [""])[0][:100]
        kind = (query.get("kind") or ["technique"])[0]
        try:
            limit = max(1, min(50, int((query.get("limit") or ["15"])[0])))
        except ValueError:
            limit = 15
        dataset = self.workspace.dataset
        if kind == "technique":
            return {"results": [
                {"id": t.id, "name": t.name, "tactics": list(t.tactics), "analytics": len(t.analytics)}
                for t in dataset.search(text, limit=limit)
            ]}
        if kind not in THREAT_KINDS:
            raise ApiError(HTTPStatus.BAD_REQUEST, "kind must be technique, group, software or campaign")
        return {"results": [
            {"id": p.id, "name": p.name, "aliases": list(p.aliases[:5]), "techniques": len(p.technique_ids),
             "kind": p.kind}
            for p in dataset.search_threats(text, kind, limit=limit)
        ]}

    def technique(self, identifier: str) -> dict[str, Any]:
        with self._lock:
            technique = self.workspace.dataset.get_technique(identifier)
            return self.workspace.technique_dict(technique, include_coverage=True)

    def threat(self, identifier: str, query: dict[str, list[str]]) -> dict[str, Any]:
        kind = (query.get("kind") or [None])[0]
        if kind is not None and kind not in THREAT_KINDS:
            raise ApiError(HTTPStatus.BAD_REQUEST, "kind must be group, software or campaign")
        with_campaigns = (query.get("with_campaigns") or ["false"])[0] == "true"
        profile = self.workspace.resolve_threat(identifier, kind, with_campaigns=with_campaigns)
        return self.workspace.threat_dict(profile)

    # -- POST ----------------------------------------------------------------- #
    def generate(self, body: dict[str, Any]) -> dict[str, Any]:
        technique_id = _text(body, "technique", 12)
        if not technique_id:
            raise ApiError(HTTPStatus.BAD_REQUEST, "'technique' is required")
        options = _options_from(body)
        include_banner = body.get("banner", True) is not False
        with self._lock:
            result = self.workspace.generate_technique(technique_id, options)
        if body.get("save") is True and result.ok:
            saved = self._save_technique(result, include_banner)
        else:
            saved = []
        return self._technique_payload(result, include_banner, saved)

    def pack(self, body: dict[str, Any]) -> dict[str, Any]:
        pack, options, include_banner = self._build_pack(body)
        with self._lock:
            generator = self.workspace.generator(options)
            files, bundle_errors = render_pack_files(
                pack, self.workspace.dataset, self.workspace.bundle_options(options, generator), include_banner
            )
        saved = None
        if body.get("save") is True and pack.generated:
            with self._lock:
                written = write_pack(pack, Path(self.output_root), self.workspace.dataset,
                                     self.workspace.bundle_options(options, generator), include_banner)
            saved = str(written["folder"])
        summary = pack.to_dict()
        summary["files"] = [{"path": path, "size": len(text)} for path, text in files.items()]
        summary["rule_files"] = {path: text for path, text in files.items() if path.startswith("sigma/")}
        summary["bundle_errors"] = bundle_errors
        summary["saved_to"] = saved
        summary["slug"] = pack.slug
        return summary

    def pack_zip(self, body: dict[str, Any]) -> tuple[bytes, str]:
        pack, options, include_banner = self._build_pack(body)
        with self._lock:
            generator = self.workspace.generator(options)
            files, _ = render_pack_files(
                pack, self.workspace.dataset, self.workspace.bundle_options(options, generator), include_banner
            )
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for path, text in files.items():
                archive.writestr(f"{pack.slug}/{path}", text)
        return buffer.getvalue(), f"{pack.slug}.zip"

    def update_sigmahq(self, _body: dict[str, Any]) -> dict[str, Any]:
        if self.workspace.offline:
            raise ApiError(HTTPStatus.CONFLICT, "The UI was started with --offline; downloads are disabled.")
        with self._lock:
            index = download_index(default_index_path(self.workspace.sigmahq_path))
            self.workspace._sigmahq = index
        return {"release": index.release, "rules": len(index.rules)}

    # -- internals ------------------------------------------------------------ #
    def _build_pack(self, body: dict[str, Any]):
        query = _text(body, "query", 100)
        if not query:
            raise ApiError(HTTPStatus.BAD_REQUEST, "'query' is required")
        kind = _text(body, "kind", 10, tuple(THREAT_KINDS))
        options = _options_from(body)
        include_banner = body.get("banner", True) is not False
        with self._lock:
            pack = self.workspace.build_pack(query, kind, options)
        return pack, options, include_banner

    def _save_technique(self, result: TechniqueResult, include_banner: bool) -> list[str]:
        root = Path(self.output_root)
        paths = []
        for rule in list(result.rules) + list(result.chains):
            paths.append(str(write_text(root / "sigma" / rule.filename(), rule.to_yaml(include_banner=include_banner))))
        if result.bundle is not None:
            name = f"{result.technique.id.lower().replace('.', '_')}.json"
            paths.append(str(write_text(root / "stix" / name, dump_bundle(result.bundle))))
        return paths

    def _technique_payload(self, result: TechniqueResult, include_banner: bool, saved: list[str]) -> dict[str, Any]:
        technique = result.technique
        return {
            "requested": result.requested_id,
            "technique": {"id": technique.id, "name": technique.name, "url": technique.url} if technique else None,
            "status": result.status,
            "reason": result.reason,
            "warnings": result.warnings,
            "rules": [_rule_payload(r, include_banner, result.problems.get(r.filename(), [])) for r in result.rules],
            "chains": [_rule_payload(c, include_banner, result.problems.get(c.filename(), [])) for c in result.chains],
            "bundle": {
                "filename": f"{technique.id.lower().replace('.', '_')}.json",
                "json": dump_bundle(result.bundle),
                "objects": _object_counts(result.bundle),
                "problems": result.problems.get("bundle", []),
            } if result.bundle and technique else None,
            "coverage": result.coverage.to_dict() if result.coverage else None,
            "saved": saved,
        }


# --------------------------------------------------------------------------- #
# HTTP plumbing
# --------------------------------------------------------------------------- #
_TECHNIQUE_PATH = re.compile(r"^/api/technique/([A-Za-z0-9.]{1,12})$")
_THREAT_PATH = re.compile(r"^/api/threat/([^/]{1,100})$")


def make_handler(app: WebApp, allowed_hosts: set[str]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"sigma-generator/{__version__}"
        sys_version = ""
        # Socket read/write timeout: a client that announces a body and never sends
        # it cannot hold a server thread forever.  Rule generation is not affected.
        timeout = 60

        # -- plumbing ---------------------------------------------------------- #
        def log_message(self, fmt: str, *args: Any) -> None:  # route access logs to -vv
            LOG.debug("%s - %s", self.address_string(), fmt % args)

        def _send(self, status: HTTPStatus, body: bytes, content_type: str,
                  extra: Optional[dict[str, str]] = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in {**SECURITY_HEADERS, **(extra or {})}.items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: HTTPStatus, payload: Any) -> None:
            self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _host_allowed(self) -> bool:
            host = (self.headers.get("Host") or "").lower()
            if host in allowed_hosts:
                return True
            self._json(HTTPStatus.FORBIDDEN, {"error": "Host header not allowed"})
            return False

        def _dispatch(self, action: Callable[[], Any]) -> None:
            try:
                result = action()
            except ApiError as exc:
                self._json(exc.status, {"error": exc.message})
            except SigmaGeneratorError as exc:
                self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": str(exc)})
            except Exception as exc:  # never leak a stack trace to the page
                LOG.exception("Unhandled error while serving %s", self.path)
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"Internal error: {type(exc).__name__}"})
            else:
                if isinstance(result, tuple):   # (bytes, filename) download
                    data, filename = result
                    safe = slugify(filename.rsplit(".", 1)[0]) + ".zip"
                    self._send(HTTPStatus.OK, data, "application/zip",
                               {"Content-Disposition": f'attachment; filename="{safe}"'})
                else:
                    self._json(HTTPStatus.OK, result)

        # -- verbs --------------------------------------------------------------- #
        def do_HEAD(self) -> None:  # noqa: N802 - http.server naming
            self.do_GET()

        def do_GET(self) -> None:  # noqa: N802
            if not self._host_allowed():
                return
            parsed = urlparse(self.path)
            path, query = parsed.path, parse_qs(parsed.query)

            if path in STATIC_FILES:
                filename, content_type = STATIC_FILES[path]
                self._send(HTTPStatus.OK, (STATIC_DIR / filename).read_bytes(), content_type)
                return
            if path == "/api/status":
                self._dispatch(lambda: app.status(query))
                return
            if path == "/api/search":
                self._dispatch(lambda: app.search(query))
                return
            match = _TECHNIQUE_PATH.match(path)
            if match:
                self._dispatch(lambda: app.technique(match.group(1)))
                return
            match = _THREAT_PATH.match(path)
            if match:
                self._dispatch(lambda: app.threat(unquote(match.group(1)), query))
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        def _read_body(self) -> Optional[bytes]:
            """The request body, or ``None`` when its length is invalid or over the cap.

            The body is consumed even when the request is about to be rejected:
            closing a socket with unread data resets the connection (on Windows in
            particular), and the client then sees an abort instead of the error.
            An oversized body is drained up to a bound and the connection closed.
            """
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if 0 <= length <= MAX_BODY_BYTES:
                return self.rfile.read(length)
            self.close_connection = True
            remaining = min(length, MAX_DRAIN_BYTES) if length > 0 else 0
            try:
                while remaining > 0:
                    chunk = self.rfile.read(min(remaining, MAX_BODY_BYTES))
                    if not chunk:
                        break
                    remaining -= len(chunk)
            except OSError:
                pass
            return None

        def do_POST(self) -> None:  # noqa: N802
            raw = self._read_body()
            if not self._host_allowed():
                return
            routes = {
                "/api/generate": app.generate,
                "/api/pack": app.pack,
                "/api/pack.zip": app.pack_zip,
                "/api/sigmahq/update": app.update_sigmahq,
            }
            handler = routes.get(urlparse(self.path).path)
            if handler is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
                return
            if self.headers.get(REQUIRED_HEADER) != "sigma-generator":
                self._json(HTTPStatus.FORBIDDEN, {"error": f"Missing {REQUIRED_HEADER} header"})
                return
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "Content-Type must be application/json"})
                return
            if raw is None:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Request body too large"})
                return
            try:
                body = json.loads(raw or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "Body is not valid JSON"})
                return
            if not isinstance(body, dict):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "Body must be a JSON object"})
                return
            self._dispatch(lambda: handler(body))

        def do_PUT(self) -> None:  # noqa: N802
            self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "Method not allowed"})

        do_DELETE = do_PATCH = do_PUT

    return Handler


def allowed_host_headers(host: str, port: int) -> set[str]:
    names = {host.lower(), "localhost", "127.0.0.1", "[::1]"}
    return {f"{name}:{port}" for name in names} | ({host.lower()} if port == 80 else set())


def create_server(workspace: Workspace, host: str = "127.0.0.1", port: int = 8765,
                  output_root: Optional[Path] = None) -> ThreadingHTTPServer:
    app = WebApp(workspace, output_root)
    allowed: set[str] = set()
    server = ThreadingHTTPServer((host, port), make_handler(app, allowed))
    # Port 0 means "any free port" - the real port is only known after binding.
    allowed.update(allowed_host_headers(host, server.server_address[1]))
    server.daemon_threads = True
    return server


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def serve(workspace: Workspace, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> int:
    if not _is_loopback(host):
        LOG.warning("Binding to %s exposes the UI - which can write files - to your network. "
                    "Only do this on a trusted network.", host)

    print("Loading ATT&CK data...")
    workspace.dataset  # load before accepting requests so the first page is fast
    try:
        server = create_server(workspace, host, port)
    except OSError as exc:
        print(f"Could not start the web interface on {host}:{port}: {exc}")
        print("Is it already running? Try another port with --port 8766")
        return 1

    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{server.server_address[1]}/"
    print(f"sigma-generator UI running at {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0
