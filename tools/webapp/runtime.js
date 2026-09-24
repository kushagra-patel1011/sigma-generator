// Runs the generator in the browser and answers the page's /api/... calls from it.
//
// The page (app.js) is the same file the local server ships: it calls fetch()
// against /api/... paths.  Here those calls are intercepted and handed to the
// real Python code running in Pyodide, so there is no server and nothing leaves
// the browser.  Anything not starting with /api/ is fetched normally.
(() => {
  "use strict";

  const PYODIDE = "https://cdn.jsdelivr.net/pyodide/v0.28.3/full/";
  const status = document.getElementById("boot-status");
  const detail = document.getElementById("boot-detail");
  const overlay = document.getElementById("boot");
  const bar = document.getElementById("boot-bar");

  let step = 0;
  const STEPS = 6;
  function progress(message, note) {
    step += 1;
    if (status) status.textContent = message;
    if (detail && note !== undefined) detail.textContent = note;
    if (bar) bar.style.width = `${Math.round((step / STEPS) * 100)}%`;
  }

  function failed(error) {
    if (status) status.textContent = "Could not start";
    if (detail) {
      detail.textContent = `${error}. A recent desktop browser is needed; ` +
        "private windows with storage disabled can also block this.";
    }
    if (bar) bar.style.background = "var(--danger, #c0392b)";
    console.error(error);
  }

  // Fetch with a readable progress note, so a 3 MB download is not a blank wait.
  async function fetchBytes(url, label) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`${url} -> HTTP ${response.status}`);
    const total = Number(response.headers.get("Content-Length") || 0);
    if (!response.body || !total) return new Uint8Array(await response.arrayBuffer());
    const reader = response.body.getReader();
    const chunks = [];
    let received = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
      if (detail) detail.textContent = `${label} ${(received / 1e6).toFixed(1)} of ${(total / 1e6).toFixed(1)} MB`;
    }
    const bytes = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return bytes;
  }

  const DISPATCHER = `
import io, json, mimetypes, traceback
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs, unquote

from sigma_generator.service import Workspace
from sigma_generator.utils import SigmaGeneratorError
from sigma_generator.web.server import ApiError, WebApp, _TECHNIQUE_PATH, _THREAT_PATH

_sigmahq = "/data/sigmahq.json" if Path("/data/sigmahq.json").is_file() else None
_app = WebApp(Workspace(data_path="/data/attack.json", sigmahq_path=_sigmahq, offline=True),
              output_root=Path("/tmp/output"))


def handle(method, path, search, body_json):
    """Mirror of the routing in web/server.py, minus the HTTP plumbing."""
    query = parse_qs(search.lstrip("?"))
    body = json.loads(body_json) if body_json else {}
    if isinstance(body, dict):
        body["save"] = False          # there is no disk to save to in a browser
    try:
        if method == "GET":
            if path == "/api/status":
                return _ok(_app.status(query))
            if path == "/api/search":
                return _ok(_app.search(query))
            match = _TECHNIQUE_PATH.match(path)
            if match:
                return _ok(_app.technique(match.group(1)))
            match = _THREAT_PATH.match(path)
            if match:
                return _ok(_app.threat(unquote(match.group(1)), query))
        elif method == "POST":
            if path == "/api/generate":
                return _ok(_app.generate(body))
            if path == "/api/pack":
                return _ok(_app.pack(body))
            if path == "/api/pack.zip":
                data, filename = _app.pack_zip(body)
                return {"status": 200, "type": "application/zip", "filename": filename,
                        "body": data}
            if path == "/api/sigmahq/update":
                raise ApiError(HTTPStatus.CONFLICT,
                               "This build ships a fixed SigmaHQ index; run the tool locally to refresh it.")
        return _error(404, "Not found")
    except ApiError as exc:
        return _error(int(exc.status), exc.message)
    except SigmaGeneratorError as exc:
        return _error(422, str(exc))
    except Exception as exc:
        traceback.print_exc()
        return _error(500, f"Internal error: {type(exc).__name__}")


def _ok(payload):
    return {"status": 200, "type": "application/json; charset=utf-8",
            "body": json.dumps(payload, ensure_ascii=False)}


def _error(status, message):
    return {"status": status, "type": "application/json; charset=utf-8",
            "body": json.dumps({"error": message})}
`;

  async function boot() {
    progress("Loading Python runtime", "about 10 MB, cached by the browser afterwards");
    const pyodideScript = document.createElement("script");
    pyodideScript.src = `${PYODIDE}pyodide.js`;
    const ready = new Promise((resolve, reject) => {
      pyodideScript.onload = resolve;
      pyodideScript.onerror = () => reject(new Error("Could not load the Python runtime"));
    });
    document.head.appendChild(pyodideScript);
    await ready;

    const pyodide = await loadPyodide({ indexURL: PYODIDE });

    progress("Loading YAML support");
    await pyodide.loadPackage(["pyyaml", "micropip"]);

    progress("Installing the generator");
    const micropip = pyodide.pyimport("micropip");
    // deps: false - the wheel declares requests for downloading ATT&CK, which
    // this build never does: the data is already here and offline mode is on.
    await micropip.install.callKwargs(
      new URL(document.body.dataset.wheel, document.baseURI).href, { deps: false });

    progress("Downloading ATT&CK data", "");
    const attack = await fetchBytes(new URL("attack.json", document.baseURI).href, "ATT&CK data");
    pyodide.FS.mkdirTree("/data");
    pyodide.FS.writeFile("/data/attack.json", attack);

    try {
      const index = await fetchBytes(new URL("sigmahq.json", document.baseURI).href, "SigmaHQ index");
      pyodide.FS.writeFile("/data/sigmahq.json", index);
    } catch (error) {
      console.warn("SigmaHQ index unavailable; gap checks are off", error);
    }

    progress("Reading ATT&CK", "parsing a few hundred techniques");
    await pyodide.runPythonAsync(DISPATCHER);
    const handle = pyodide.globals.get("handle");

    const nativeFetch = window.fetch.bind(window);
    window.fetch = async (input, init = {}) => {
      const url = typeof input === "string" ? input : input.url;
      const path = url.startsWith("http") ? new URL(url).pathname : url.split("?")[0];
      if (!path.startsWith("/api/")) return nativeFetch(input, init);

      const search = url.includes("?") ? url.slice(url.indexOf("?")) : "";
      const method = (init.method || "GET").toUpperCase();
      const result = handle(method, path, search, init.body || "").toJs({ dict_converter: Object.fromEntries });
      const headers = { "Content-Type": result.type };
      let body = result.body;
      if (result.filename) {
        headers["Content-Disposition"] = `attachment; filename="${result.filename}"`;
        body = body instanceof Uint8Array ? body : new Uint8Array(body);
      }
      return new Response(body, { status: result.status, headers });
    };

    // Parse the bundle now, while the loading screen is still up, so the first
    // search does not sit on a cold dataset.
    handle("GET", "/api/status", "", "");

    progress("Ready", "");
    overlay.hidden = true;
    document.body.classList.add("ready");
    window.dispatchEvent(new Event("runtime-ready"));

    const page = document.createElement("script");
    page.src = "app.js";
    // app.js starts itself on DOMContentLoaded, which fired long before it was
    // added to the page, so its listener would never run. Re-dispatch it.
    page.onload = () => document.dispatchEvent(new Event("DOMContentLoaded"));
    document.body.appendChild(page);
  }

  boot().catch(failed);
})();
