"""Build the browser build of the web UI: no server, no install, no clone.

The page runs the real generator inside the visitor's browser with Pyodide
(CPython compiled to WebAssembly).  Nothing is sent anywhere: the ATT&CK data
and the code are static files, and every rule is generated locally.

    python -m tools.webapp build [--output docs]

What it assembles:

* ``attack.json``   - the pinned ATT&CK release with the objects and fields the
  generator never reads stripped out (52 MB -> ~19 MB, ~3 MB over the wire).
  ``--check`` proves the trimmed copy generates byte-identical output.
* ``sigmahq.json``  - the SigmaHQ coverage index, copied as-is.
* ``*.whl``         - the package itself, installed into Pyodide with micropip.
* the UI files from ``src/web/static``, plus ``runtime.js``, which answers the
  page's ``/api/...`` calls from Python instead of from an HTTP server.
"""

from __future__ import annotations

import argparse
import gzip
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src import __version__  # noqa: E402
from src.sigmahq import default_index_path  # noqa: E402
from tools.corpus import BUNDLE_PATH, PINNED_ATTACK, fetch_bundle  # noqa: E402

STATIC_DIR = ROOT / "src" / "web" / "static"
WEBAPP_DIR = Path(__file__).resolve().parent / "webapp"
DEFAULT_OUTPUT = ROOT / "docs"

#: STIX objects the generator reads.  Everything else (mitigations, data
#: sources' prose, identities, markings, matrices) is dropped.
KEEP_TYPES = frozenset({
    "attack-pattern", "x-mitre-detection-strategy", "x-mitre-analytic",
    "x-mitre-data-component", "x-mitre-data-source",
    "intrusion-set", "malware", "tool", "campaign", "relationship", "x-mitre-collection",
})
#: Relationship kinds the generator follows.
KEEP_RELATIONSHIPS = frozenset({"uses", "attributed-to", "revoked-by", "subtechnique-of", "detects"})
#: Fields read anywhere in src/.  Keep this in step with attack_fetcher.py.
KEEP_FIELDS = frozenset({
    "id", "type", "spec_version", "name", "description", "created", "modified", "revoked",
    "external_references", "kill_chain_phases", "aliases",
    "x_mitre_platforms", "x_mitre_is_subtechnique", "x_mitre_version", "x_mitre_deprecated",
    "x_mitre_detection", "x_mitre_data_sources", "x_mitre_aliases", "x_mitre_domains",
    "x_mitre_log_source_references", "x_mitre_mutable_elements", "x_mitre_analytic_refs",
    "relationship_type", "source_ref", "target_ref",
})


def trim_bundle(payload: dict[str, Any]) -> dict[str, Any]:
    """The same ATT&CK content, without the parts the generator never looks at."""
    objects = []
    for obj in payload.get("objects", []):
        kind = obj.get("type")
        if kind not in KEEP_TYPES:
            continue
        if kind == "relationship" and obj.get("relationship_type") not in KEEP_RELATIONSHIPS:
            continue
        trimmed = {key: value for key, value in obj.items() if key in KEEP_FIELDS}
        references = trimmed.get("external_references")
        if isinstance(references, list):
            # The ATT&CK id and the technique's own URL are used; the citation
            # list behind them is prose the generator only ever counts.
            trimmed["external_references"] = [
                ref for ref in references if str(ref.get("source_name", "")).startswith("mitre-")
            ][:2]
        objects.append(trimmed)
    return {"type": "bundle", "id": payload.get("id"),
            "spec_version": payload.get("spec_version", "2.1"), "objects": objects}


def check_identical(full_path: Path, slim_path: Path) -> None:
    """Fail unless the trimmed bundle generates exactly what the full one does."""
    from src.attack_fetcher import AttackDataset
    from tools.corpus import build_digest

    full = build_digest(AttackDataset.from_file(full_path))
    slim = build_digest(AttackDataset.from_file(slim_path))
    full["attack"] = slim["attack"] = {}
    if full != slim:
        differing = [tid for tid, entry in full["techniques"].items()
                     if entry != slim["techniques"].get(tid)]
        raise SystemExit(
            f"Trimmed bundle changes the output for {len(differing)} technique(s): "
            f"{', '.join(differing[:5])}. Add the missing field to KEEP_FIELDS."
        )
    print(f"  identical output for {len(full['techniques'])} techniques")


def build_page(wheel_name: str) -> str:
    """The server's own page, rewired to load the in-browser runtime.

    Transformed rather than copied, so the hosted page can never drift from the
    one ``python -m src.main ui`` serves.
    """
    page = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    replacements = [
        ('href="/static/styles.css"', 'href="styles.css"'),
        # runtime.js answers the page's /api/ calls, then loads app.js itself.
        ('<script src="/static/app.js"></script>', '<script src="runtime.js"></script>'),
        ("<body>", f'<body data-wheel="{wheel_name}">\n' + (WEBAPP_DIR / "boot.html").read_text(encoding="utf-8")),
    ]
    for old, new in replacements:
        if old not in page:
            raise SystemExit(f"index.html no longer contains {old!r}; update tools/webapp.py")
        page = page.replace(old, new, 1)
    return page


def build_wheel(destination: Path) -> Path:
    """Build the package wheel that Pyodide installs."""
    for stale in destination.glob("sigma_generator-*.whl"):
        stale.unlink()
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(ROOT), "--no-deps", "--quiet", "-w", str(destination)],
        check=True,
    )
    wheels = sorted(destination.glob("sigma_generator-*.whl"))
    if not wheels:
        raise SystemExit("pip produced no wheel")
    return wheels[-1]


def build(output: Path, check: bool = False, sigmahq: Optional[Path] = None) -> None:
    output.mkdir(parents=True, exist_ok=True)
    print(f"Building the browser app into {output}")

    bundle = fetch_bundle()
    payload = json.loads(bundle.read_text(encoding="utf-8"))
    slim = trim_bundle(payload)
    attack_path = output / "attack.json"
    attack_path.write_text(json.dumps(slim, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    raw = attack_path.stat().st_size
    packed = len(gzip.compress(attack_path.read_bytes(), 9))
    print(f"  attack.json   {raw/1e6:5.1f} MB  ({packed/1e6:.1f} MB gzipped, "
          f"{len(payload['objects'])} -> {len(slim['objects'])} objects)")
    if check:
        check_identical(bundle, attack_path)

    index_path = Path(sigmahq) if sigmahq else default_index_path()
    if index_path.is_file():
        shutil.copy2(index_path, output / "sigmahq.json")
        print(f"  sigmahq.json  {(output / 'sigmahq.json').stat().st_size/1e6:5.1f} MB")
    else:
        print(f"  sigmahq.json  skipped ({index_path} is missing; gap checks will be off)")

    wheel = build_wheel(output)
    print(f"  {wheel.name}")

    shutil.copy2(STATIC_DIR / "app.js", output / "app.js")
    shutil.copy2(WEBAPP_DIR / "runtime.js", output / "runtime.js")
    (output / "styles.css").write_text(
        (STATIC_DIR / "styles.css").read_text(encoding="utf-8")
        + "\n\n/* --- browser build --- */\n"
        + (WEBAPP_DIR / "boot.css").read_text(encoding="utf-8"),
        encoding="utf-8", newline="\n",
    )
    (output / "index.html").write_text(build_page(wheel.name), encoding="utf-8", newline="\n")
    (output / ".nojekyll").write_text("", encoding="utf-8")
    manifest = {
        "version": __version__,
        "attack": {"version": PINNED_ATTACK["version"], "sha256": PINNED_ATTACK["sha256"]},
        "wheel": wheel.name,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    print(f"  index.html, app.js, styles.css, runtime.js, manifest.json")
    total = sum(p.stat().st_size for p in output.rglob("*") if p.is_file())
    print(f"Done: {total/1e6:.1f} MB on disk. Serve it with: python -m http.server -d {output}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.webapp", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)
    builder = subparsers.add_parser("build", help="assemble the static site")
    builder.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="output folder (default: docs/)")
    builder.add_argument("--sigmahq", type=Path, default=None, help="SigmaHQ index to ship")
    builder.add_argument("--check", action="store_true",
                         help="prove the trimmed bundle generates identical output (slow, ~1 min)")
    args = parser.parse_args(argv)
    build(args.output, check=args.check, sigmahq=args.sigmahq)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
