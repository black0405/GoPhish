"""Pull the Skope IT > Applications table out of the Netskope UI API.

This talks to the same internal endpoint the web console uses
(POST /rest/exportAppsList, which proxies GET /rest/app), so it needs a
browser session: the ci_session cookie and the request token from the page.

Set these before running:
    NS_TENANT=mytenant.goskope.com
    NS_COOKIE=<value of ci_session>
    NS_TOKEN=<"token" field from the request body>
"""

import csv
import json
import os
import sys
import urllib.request

TENANT = os.environ.get("NS_TENANT", "mytenant.goskope.com")
COOKIE = os.environ.get("NS_COOKIE", "")
TOKEN = os.environ.get("NS_TOKEN", "")

FIELDS = "app,category,sanctioned,cci,users,sessions,tags,numbytes,client_bytes,server_bytes"
PAGE = 1000

# Time window and filter, straight from the captured call. Epoch seconds.
STARTTIME = "1780252200"
ENDTIME = "1782844140"
QUERY = (
    "(traffic_type neq 'Web') and (usergroup in ["
    " 'AP1.OFC.LOC/India/Groups/IN_Global_netskope_AP1User',"
    " 'india.asia.gcn.local/IN/Administrative/Groups - Security/IN_Global_netskope_Alluser',"
    " 'ONE.OFC.LOC/Zone-ABI Global/Managed Objects/Managed Groups/SONEG-Netskope-ABI-GOA Team' ])"
)


def fetch_page(offset):
    body = {
        "method": "GET",
        "url": "/rest/app",
        "params": {
            "starttime": STARTTIME,
            "endtime": ENDTIME,
            "sort": "-client_bytes,app",
            "query": QUERY,
            "resource": "app",
            "limit": PAGE,
            "fields": FIELDS,
            "proxy__service": {"eventtype": "page", "value": "SEARCH_SERVICE", "sync": 0},
            "offset": offset,
        },
        "__nsConfig": {"no_loader": True},
        "token": TOKEN,
    }
    req = urllib.request.Request(
        f"https://{TENANT}/rest/exportAppsList",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Cookie": f"ci_session={COOKIE}",
            "Resource": "applications",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": f"https://{TENANT}",
            "Referer": f"https://{TENANT}/ns",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def rows_of(payload):
    """Netskope wraps results differently per endpoint; dig out the list."""
    if isinstance(payload, list):
        return payload
    for key in ("data", "result", "rows", "list"):
        val = payload.get(key)
        if isinstance(val, list):
            return val
        if isinstance(val, dict):
            return rows_of(val)
    return []


def fetch_all():
    rows, offset = [], 0
    while True:
        page = rows_of(fetch_page(offset))
        rows.extend(page)
        print(f"offset {offset}: {len(page)} rows", file=sys.stderr)
        if len(page) < PAGE:
            return rows
        offset += PAGE


def write_csv(rows, path="apps.csv"):
    cols = FIELDS.split(",")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


def selfcheck():
    assert rows_of({"data": [{"app": "x"}]}) == [{"app": "x"}]
    assert rows_of({"data": {"rows": [1, 2]}}) == [1, 2]
    assert rows_of({"status": "success"}) == []
    print("ok")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        selfcheck()
    elif not (COOKIE and TOKEN):
        sys.exit("set NS_TENANT, NS_COOKIE and NS_TOKEN first")
    else:
        rows = fetch_all()
        print(f"{len(rows)} rows -> {write_csv(rows)}")
