#!/usr/bin/env python3
"""Local test UI for phishing_report.py.

    python serve.py            ->  http://127.0.0.1:8020

Drop the source files in the browser, hit Run, read the counts, download the
reports. Stdlib only on the server side - no framework, no extra dependency
beyond what the pipeline itself already needs.
"""
import argparse
import base64
import json
import mimetypes
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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


def summarise(df):
    if not len(df):
        return {"rows": 0, "outcome": {}, "phished": {}}
    return {
        "rows": int(len(df)),
        "outcome": {(k or "(blank)"): int(v) for k, v in df[pr.COL_OUTCOME].value_counts().items()},
        "phished": {str(k): int(v) for k, v in df[pr.COL_PHISHED].value_counts().items()},
    }


def preview(df, n=25):
    cols = [c for c in PREVIEW_HEAD if c in df.columns] + pr.NEW_COLS
    head = df.loc[:, cols].head(n).astype(object).where(df.loc[:, cols].head(n).notna(), "")
    return {"columns": cols, "rows": head.astype(str).values.tolist()}


def do_run(payload):
    """payload: {key: {"name": filename, "data": base64}}. Returns the JSON reply."""
    run = RUNS / time.strftime("run_%Y%m%d_%H%M%S")
    (run / "input").mkdir(parents=True, exist_ok=True)
    logs = []

    frames = {}
    for key in SOURCES:
        up = payload.get(key)
        if not up:
            continue
        path = run / "input" / Path(up["name"]).name
        path.write_bytes(base64.b64decode(up["data"]))
        frames[key] = pr.read_any(path, NEED.get(key))
        logs.append(f"read {path.name}: {len(frames[key])} rows")

    if "base" not in frames:
        raise ValueError("The Userbase file is required")

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

    def do_POST(self):
        if self.path != "/run":
            return self.send(404, json.dumps({"error": "not found"}))
        try:
            n = int(self.headers.get("Content-Length", 0))
            # ponytail: whole upload held in memory. Fine for a local test UI;
            # switch to streamed multipart if the files stop fitting.
            payload = json.loads(self.rfile.read(n) or b"{}")
            self.send(200, json.dumps(do_run(payload)))
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
    url = f"http://127.0.0.1:{a.port}"
    print(f"phishing report test UI -> {url}   (ctrl-c to stop)")
    if not a.no_open:
        webbrowser.open(url)
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
