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
import threading
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
NEED = {"base": "Employee Email", "mimecast": "To", "o365": "SenderAddress", "soc": "User",
        "false_login": "Username", "false_login_sso": "Email",
        "gophish": "email", "gophish_de": "email"}
SOURCES = ["base", "false_login", "false_login_sso", "mimecast", "o365", "soc",
           "gophish", "gophish_de"]

XLSX_MAX_ROWS = 100_000   # csv-only above this: openpyxl writes 200k rows in 118s, 100k in ~60s
SID_RE = re.compile(r"[0-9a-zA-Z-]{8,64}$")
SESSIONS = {}  # sid -> {"dir": Path, "files": {key: Path}}
JOBS = {}      # sid -> {"state": running|done|error, "result"|"error": ...}


def start_run(payload):
    """Run in a worker thread. Browsers kill an idle request after ~5 min, so a
    big run must never hold the /run connection open - the page polls /status."""
    sid = payload.get("sid")
    session(sid)   # validates the sid
    if JOBS.get(sid, {}).get("state") == "running":
        return {"state": "running"}
    # the worker appends to this list as it goes and /status hands it back on
    # every poll, so the page shows the stage a slow run is sitting in
    logs = []
    JOBS[sid] = {"state": "running", "log": logs}

    def work():
        try:
            JOBS[sid] = {"state": "done", "result": do_run(payload, logs), "log": logs}
        except Exception as exc:
            traceback.print_exc()
            logs.append(f"! {type(exc).__name__}: {exc}")
            JOBS[sid] = {"state": "error", "error": f"{type(exc).__name__}: {exc}", "log": logs}

    threading.Thread(target=work, daemon=True).start()
    return {"state": "running"}


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
        return {"rows": 0, "outcome": {}, "gophish": {}, "phished": {},
                "o365": {}, "soc": {}, "reported": {}}
    vc = lambda col: {(k or "(blank)"): int(v) for k, v in df[col].value_counts().items()}
    return {"rows": int(len(df)), "outcome": vc(pr.COL_OUTCOME), "gophish": vc(pr.COL_GOPHISH),
            "phished": vc(pr.COL_PHISHED), "o365": vc(pr.COL_O365),
            "soc": vc(pr.COL_SOC), "reported": vc(pr.COL_REPORTED)}


def do_run(payload, logs=None):
    """payload: {"sid": ...} - the files are already on disk from /upload.

    `logs` is the live list /status streams back; stages announce themselves
    before they start and rewrite their own line with the timing when they
    finish, so a stalled run names the file it is stuck on."""
    sess = session(payload.get("sid"))
    run, uploaded = sess["dir"], sess["files"]
    if "base" not in uploaded:
        raise ValueError("The Userbase file is required")

    started = time.perf_counter()
    logs = [] if logs is None else logs
    logs.append(pr.XL_NOTE)

    def stage(msg):
        """Append '<msg>…' now; the returned call closes it out with the timing."""
        logs.append(f"{msg}…")
        i, t = len(logs) - 1, time.perf_counter()

        def done(text):
            line = f"{text} ({time.perf_counter() - t:.1f}s)"
            if len(logs) - 1 == i:      # nothing streamed under it - rewrite in place
                logs[i] = line
            else:                       # sub-steps landed below, so close it off below them
                logs[i] = f"{msg}:"
                logs.append(line)

        return done

    frames = {}
    for key in SOURCES:
        if key in uploaded:
            name, mb = uploaded[key].name, uploaded[key].stat().st_size / 1e6
            done = stage(f"reading {name} ({mb:.1f} MB)")
            frames[key] = pr.read_any(uploaded[key], NEED.get(key))
            done(f"read {name}: {len(frames[key])} rows")

    done = stage("running the lookups")
    final, sheets = pr.run(log=logs.append, **frames)
    done("lookups done")

    # step 4's GoPhish sheets ride in the same workbook as the report, so a run
    # is still one download. Sheet names are what the SOP calls them.
    rows = len(final)
    stem = "Final_Report"
    files = []
    if rows <= XLSX_MAX_ROWS:
        tabs = {"Final Report": final, **sheets}
        done = stage(f"writing {stem}.xlsx ({rows} rows, {len(tabs)} sheets)")
        pr.write_xlsx(run / f"{stem}.xlsx", tabs)
        done(f"wrote {stem}.xlsx")
        files.append(f"{stem}.xlsx")
    else:   # openpyxl writes ~1000 rows/s, so past the cap the report is csv and
            # the GoPhish sheets - which come from the much smaller events file -
            # go to their own workbook rather than being dropped
        done = stage(f"writing {stem}.csv ({rows} rows, too many for xlsx)")
        final.to_csv(run / f"{stem}.csv", index=False)
        done(f"wrote {stem}.csv")
        files.append(f"{stem}.csv")
        if sheets:
            done = stage(f"writing GoPhish_Sheets.xlsx ({len(sheets)} sheets)")
            pr.write_xlsx(run / "GoPhish_Sheets.xlsx", sheets)
            done("wrote GoPhish_Sheets.xlsx")
            files.append("GoPhish_Sheets.xlsx")
    logs.append(f"total {time.perf_counter() - started:.1f}s")

    return {"run": run.name, "log": logs,
            "files": [{"name": n, "url": f"/runs/{run.name}/{n}"} for n in files],
            "final": summarise(final)}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"   # keep-alive; send() always sets Content-Length

    def drain(self):
        """Discard whatever of the request body is still unread. Responding while
        body bytes are in flight makes the OS reset the connection, and the
        browser then reports a bare 'Failed to fetch' instead of our error."""
        left = getattr(self, "_unread", 0)
        while left > 0:
            chunk = self.rfile.read(min(1 << 20, left))
            if not chunk:
                break
            left -= len(chunk)
        self._unread = 0

    def send(self, code, body, ctype="application/json"):
        body = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        path = url.path
        if path == "/health":
            return self.send(200, json.dumps({"ok": True}))
        if path == "/status":
            sid = parse_qs(url.query).get("sid", [""])[0]
            return self.send(200, json.dumps(JOBS.get(sid, {"state": "unknown"})))
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
                self._unread = left

        sess["files"][key] = dest
        print(f"  uploaded {key}: {name} ({dest.stat().st_size / 1e6:.1f} MB)")
        return {"key": key, "name": name, "bytes": dest.stat().st_size}

    def do_POST(self):
        url = urlparse(self.path)
        self._unread = int(self.headers.get("Content-Length", 0))
        try:
            if url.path == "/upload":
                self.send(200, json.dumps(self.take_upload(parse_qs(url.query))))
            elif url.path == "/run":
                body = self.rfile.read(self._unread) if self._unread else b""
                self._unread = 0
                self.send(200, json.dumps(start_run(json.loads(body or b"{}"))))
            else:
                self.drain()
                self.send(404, json.dumps({"error": "not found"}))
        except Exception as exc:
            traceback.print_exc()
            self.drain()   # finish reading the body or the browser sees a reset, not our error
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
    print(pr.XL_NOTE)
    if not a.no_open:
        webbrowser.open(url)
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
