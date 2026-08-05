#!/usr/bin/env python3
"""Local test UI for phishing_report.py.

    python serve.py            ->  http://127.0.0.1:8020

Drop the source files in the browser, hit Run, read the counts, download the
reports. Stdlib only on the server side - no framework, no extra dependency
beyond what the pipeline itself already needs.

Each file is streamed to disk on its own POST /upload the moment it is picked,
so neither the page nor the server ever holds a whole export in memory; /run
then only has to name the session.
"""
import argparse
import json
import mimetypes
import re
import sys
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import phishing_report as pr

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
RUNS = ROOT / "runs"

# key -> the column read_any looks for when the export has banner rows above the header
NEED = {"base": "Employee Email", "mimecast": "To", "gophish": "email",
        "o365": "SenderAddress", "soc": "User", "gophish_de": "email"}
SOURCES = ["base", "false_login", "false_login_sso", "mimecast",
           "gophish", "o365", "soc", "gophish_de"]
PREVIEW_HEAD = ["Employee Name", "Employee Email", "Country", "Zone"]

SID_RE = re.compile(r"[0-9a-zA-Z-]{8,64}$")
SESSIONS = {}  # sid -> {"dir": Path, "files": {key: Path}}


def session(sid):
    """Folder is derived from the sid and the file map is rebuilt from disk, so
    an upload survives a server restart between picking files and hitting Run."""
    if not SID_RE.match(sid or ""):
        raise ValueError("bad session id")
    if sid not in SESSIONS:
        run = RUNS / f"run_{sid[:8]}"
        files = {p.name.split("__", 1)[0]: p
                 for p in sorted((run / "input").glob("*__*"))} if (run / "input").is_dir() else {}
        SESSIONS[sid] = {"dir": run, "files": files}
    return SESSIONS[sid]


def summarise(df):
    if not len(df):
        return {"rows": 0, "outcome": {}, "phished": {}, "o365": {}, "soc": {}, "reported": {}}
    vc = lambda col: {(k or "(blank)"): int(v) for k, v in df[col].value_counts().items()}
    return {"rows": int(len(df)), "outcome": vc(pr.COL_OUTCOME), "phished": vc(pr.COL_PHISHED),
            "o365": vc(pr.COL_O365), "soc": vc(pr.COL_SOC), "reported": vc(pr.COL_REPORTED)}


def preview(df, n=25):
    # step 1 columns only, while that is all the UI exposes
    cols = [c for c in PREVIEW_HEAD if c in df.columns] + [pr.COL_O365, pr.COL_SOC, pr.COL_REPORTED]
    head = df.loc[:, cols].head(n).astype(object).where(df.loc[:, cols].head(n).notna(), "")
    return {"columns": cols, "rows": head.astype(str).values.tolist()}


def do_run(payload):
    """payload: {"sid": ...} - the files are already on disk from /upload."""
    sess = session(payload.get("sid"))
    run, uploaded = sess["dir"], sess["files"]
    if "base" not in uploaded:
        raise ValueError("The Userbase file is required")

    logs = []
    frames = {}
    for key in SOURCES:
        if key in uploaded:
            frames[key] = pr.read_any(uploaded[key], NEED.get(key))
            logs.append(f"read {uploaded[key].name}: {len(frames[key])} rows")

    final, ger, tabs = pr.run(log=logs.append, **frames)

    files = []
    def emit(name, sheets):
        pr.write_xlsx(run / name, sheets)
        files.append({"name": name, "url": f"/runs/{run.name}/{name}"})

    emit("Final_Report.xlsx", {"Final Report": final})
    emit("German_Report.xlsx", {"German Report": ger})
    if tabs:
        emit("GoPhish_Tabs.xlsx", tabs)

    return {"run": run.name, "log": logs, "files": files,
            "final": summarise(final), "german": summarise(ger),
            "preview": preview(final), "preview_de": preview(ger)}


class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, ctype="application/json"):
        body = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/health":
            return self.send(200, json.dumps({"ok": True}))
        if path.startswith("/runs/"):
            target = (RUNS / path[len("/runs/"):]).resolve()
            if RUNS.resolve() not in target.parents or not target.is_file():
                return self.send(404, json.dumps({"error": "not found"}))
        else:
            target = WEB / (path.lstrip("/") or "index.html")
            if not target.is_file():
                return self.send(404, json.dumps({"error": "not found"}))
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send(200, target.read_bytes(), ctype)

    def take_upload(self, query):
        """Stream one raw-body upload straight to disk. Never buffers the file."""
        sid = query.get("sid", [""])[0]
        key = query.get("key", [""])[0]
        if key not in SOURCES:
            raise ValueError(f"unknown source {key!r}")
        sess = session(sid)
        name = Path(unquote(query.get("name", ["upload"])[0])).name or "upload"

        dest = sess["dir"] / "input" / f"{key}__{name}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        left = int(self.headers.get("Content-Length", 0))
        with open(dest, "wb") as fh:
            while left > 0:
                chunk = self.rfile.read(min(1 << 20, left))
                if not chunk:
                    raise ValueError("upload ended early")
                fh.write(chunk)
                left -= len(chunk)

        sess["files"][key] = dest
        print(f"  uploaded {key}: {name} ({dest.stat().st_size / 1e6:.1f} MB)")
        return {"key": key, "name": name, "bytes": dest.stat().st_size}

    def do_POST(self):
        url = urlparse(self.path)
        try:
            if url.path == "/upload":
                self.send(200, json.dumps(self.take_upload(parse_qs(url.query))))
            elif url.path == "/run":
                n = int(self.headers.get("Content-Length", 0))
                self.send(200, json.dumps(do_run(json.loads(self.rfile.read(n) or b"{}"))))
            else:
                self.send(404, json.dumps({"error": "not found"}))
        except Exception as exc:
            traceback.print_exc()
            self.send(400, json.dumps({"error": f"{type(exc).__name__}: {exc}"}))

    def log_message(self, fmt, *a):
        print(f"  {self.command} {self.path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8020)
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()

    RUNS.mkdir(exist_ok=True)
    sys.stdout.reconfigure(line_buffering=True)  # so the log is readable while it runs
    url = f"http://127.0.0.1:{a.port}"
    print(f"phishing report test UI -> {url}   (ctrl-c to stop)")
    if not a.no_open:
        webbrowser.open(url)
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
