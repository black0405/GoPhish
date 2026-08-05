#!/usr/bin/env python3
"""Phishing report preparation.

Implements steps.txt: Part 1 (non-German) on the whole Userbase file, then
Part 2 (German) on the Country = Germany subset of that result.

    python phishing_report.py --base UserBase_V2.xlsx \
        --false-login "False_login_data-Q2-Submitted.xlsx" \
        --false-login-sso "false_login_sso_data-Q2-Clicked Link.xlsx" \
        --mimecast mimecast_combine.xlsx \
        --gophish GoPhish_Events_non_german.xlsx \
        --o365 "User Reported-Microsoft 365Report button.xlsx" \
        --soc "User Reported SOC-Support.xlsx" \
        --gophish-de Events_GermanOnly.xlsx \
        --out output

Any source may be omitted; its step is skipped and reported as skipped.
Run `python phishing_report.py --selftest` to check the rules.
"""
import argparse
import re
import sys
from pathlib import Path

import pandas as pd

COL_OUTCOME = "Outcome"
COL_GOPHISH = "GoPhish"
COL_O365 = "Reported to O365"
COL_SOC = "Reported to SOC"
COL_REPORTED = "Reported (Yes/No)"
COL_PHISHED = "Phished Yes/No"  # header per "files & column.txt"; steps.txt writes it "Phished (Yes/No)"
NEW_COLS = [COL_OUTCOME, COL_GOPHISH, COL_O365, COL_SOC, COL_REPORTED, COL_PHISHED]

ID_COLS = ["Employee Email", "SSOUPN as per Saviynt", "SSOUPN as per AD (O365)"]
PHISHED_YES = {"Submitted Data", "Clicked Link"}
MIMECAST_SEVERITY = {"Email Sent": 0, "Email Opened": 1, "User Click": 2}
DE_EVENTS = ["Email Sent", "Clicked Link", "Submitted Data"]  # low -> high precedence


def norm(s):
    """Normalise an identity column to a bare lowercase email where possible."""
    s = s.astype("string").str.strip().str.strip("\"'<>").str.lower()
    s = s.str.replace(r"^mailto:", "", regex=True)
    out = s.str.extract(r"([^\s<>,;]+@[^\s<>,;]+)", expand=False).fillna(s)
    return out.replace({"": pd.NA})


def keys(df, cols):
    out = set()
    for c in cols:
        if c in df.columns:
            out |= set(norm(df[c]).dropna())
    return out


def read_any(path, need=None):
    """Read csv/xlsx as text. If `need` is missing, look for it in the first rows."""
    p = Path(path)
    csv = p.suffix.lower() in (".csv", ".txt")
    rd = (lambda **k: pd.read_csv(p, dtype=str, **k)) if csv else (lambda **k: pd.read_excel(p, dtype=str, **k))
    df = rd()
    if need and need not in df.columns:
        probe = rd(header=None, nrows=15)
        for i in range(len(probe)):
            if need in [str(v).strip() for v in probe.iloc[i]]:
                return rd(header=i)
    return df


def clean_gophish(g):
    """3.1 - drop rows whose details mention Linux but not Android."""
    d = g["details"].astype(str)
    drop = d.str.contains("linux", case=False, na=False) & ~d.str.contains("android", case=False, na=False)
    return g.loc[~drop].copy()


def split_events(g, events):
    """3.2 - one frame per event value found in `message`."""
    m = g["message"].astype(str).str.strip().str.casefold()
    return {e: g.loc[m == e.casefold()].copy() for e in events}


def phished(outcome):
    return outcome.isin(PHISHED_YES).map({True: "Yes", False: "No"})


def run(base, false_login=None, false_login_sso=None, mimecast=None, gophish=None,
        o365=None, soc=None, gophish_de=None, log=print):
    """Returns (final_report, german_report, {tab name: frame})."""
    base = base.copy()
    for c in NEW_COLS:
        base[c] = ""

    ident = {c: norm(base[c]) for c in ID_COLS if c in base.columns}
    if not ident:
        raise SystemExit("Base file has none of: " + ", ".join(ID_COLS))
    if "Employee Email" not in ident:
        raise SystemExit("Base file needs an 'Employee Email' column")
    missing = [c for c in ID_COLS if c not in ident]
    if missing:
        log(f"! base file has no {', '.join(missing)} - matching on the rest")

    def matched(src, cols, email_only=False):
        k = keys(src, cols)
        cols_ = ["Employee Email"] if email_only else list(ident)
        m = pd.Series(False, index=base.index)
        for c in cols_:
            m |= ident[c].isin(k)
        return m

    def step(n, name, ok):
        log(f"{'  ' if ok else '- '}{n} {name}" + ("" if ok else " (skipped, no file)"))

    tabs = {}

    # --- Part 1, step 2: outcomes. Applied weakest first so the strongest
    # evidence for a user is the value left standing.
    step("2.3", "Mimecast activity", mimecast is not None)
    if mimecast is not None:
        mm = mimecast.copy()
        mm["_k"] = norm(mm["To"])
        mm["_v"] = mm["Log Type"].astype(str).str.strip()
        mm["_r"] = mm["_v"].map(MIMECAST_SEVERITY).fillna(0)
        mm = mm.dropna(subset=["_k"]).sort_values("_r").drop_duplicates("_k", keep="last")
        v = ident["Employee Email"].map(dict(zip(mm["_k"], mm["_v"])))
        base.loc[v.notna(), COL_OUTCOME] = v[v.notna()]

    step("2.2", "Clicked Link (false_login_sso)", false_login_sso is not None)
    if false_login_sso is not None:
        base.loc[matched(false_login_sso, ["Email", "Username", "Email (SSO)"]), COL_OUTCOME] = "Clicked Link"

    step("2.1", "Submitted Data (false_login)", false_login is not None)
    if false_login is not None:
        base.loc[matched(false_login, ["Email (SSO)", "Username", "Email"]), COL_OUTCOME] = "Submitted Data"

    # --- step 3: GoPhish
    step("3", "GoPhish activity", gophish is not None)
    if gophish is not None:
        g = clean_gophish(gophish)
        log(f"    removed {len(gophish) - len(g)} Linux (non-Android) rows")
        for name, frame in split_events(g, ["Clicked Link", "Email Sent"]).items():
            tabs[f"GoPhish {name}"] = frame
            base.loc[matched(frame, ["email"], email_only=True), COL_GOPHISH] = name

    # --- step 4: reporting
    step("4.1", "Reported to O365", o365 is not None)
    if o365 is not None:
        base.loc[matched(o365, ["SenderAddress"], email_only=True), COL_O365] = COL_O365

    step("4.2", "Reported to SOC", soc is not None)
    if soc is not None:
        base.loc[matched(soc, ["User"], email_only=True), COL_SOC] = COL_SOC

    base[COL_REPORTED] = (base[COL_O365].ne("") | base[COL_SOC].ne("")).map({True: "Yes", False: "No"})

    # --- step 5: reconcile. Rule 2 runs second, so a confirmed GoPhish click
    # beats the "they reported it" downgrade.
    log("  5   reconcile Outcome")
    click = base[COL_OUTCOME].eq("User Click")
    base.loc[click & base[COL_REPORTED].eq("Yes"), COL_OUTCOME] = "Email Opened"
    base.loc[click & base[COL_GOPHISH].eq("Clicked Link"), COL_OUTCOME] = "Clicked Link"

    # --- step 6
    base[COL_PHISHED] = phished(base[COL_OUTCOME])

    # --- Part 2: German
    ger = pd.DataFrame(columns=base.columns)
    if "Country" in base.columns:
        ger = base[base["Country"].astype(str).str.strip().str.casefold() == "germany"].copy()
    log(f"  DE  {len(ger)} Germany users")

    if len(ger) and gophish_de is not None:
        gd = clean_gophish(gophish_de)
        log(f"    removed {len(gophish_de) - len(gd)} Linux (non-Android) rows")
        de_ident = norm(ger["Employee Email"])
        for name, frame in split_events(gd, DE_EVENTS).items():
            tabs[f"German GoPhish {name}"] = frame
            ger.loc[de_ident.isin(keys(frame, ["email"])), COL_GOPHISH] = name

        gp = ger[COL_GOPHISH]
        uc = ger[COL_OUTCOME].eq("User Click") & gp.isin(DE_EVENTS)
        ger.loc[uc & ger[COL_REPORTED].eq("Yes"), COL_OUTCOME] = "Email Opened"
        rule2 = uc & ger[COL_REPORTED].eq("No")
        ger.loc[rule2, COL_OUTCOME] = gp[rule2]
        ger[COL_PHISHED] = phished(ger[COL_OUTCOME])
    elif len(ger):
        log("    German GoPhish file not given - German reconciliation skipped")

    return base, ger, tabs


def write_xlsx(path, sheets):
    with pd.ExcelWriter(path, engine="openpyxl") as w:
        for name, frame in sheets.items():
            frame.to_excel(w, sheet_name=name[:31], index=False)


def counts(df):
    if not len(df):
        return "  (empty)"
    o = df[COL_OUTCOME].replace("", "(blank)").value_counts()
    p = df[COL_PHISHED].value_counts()
    return ("  Outcome: " + ", ".join(f"{k}={v}" for k, v in o.items()) +
            "\n  Phished: " + ", ".join(f"{k}={v}" for k, v in p.items()))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", help="Userbase file")
    ap.add_argument("--false-login")
    ap.add_argument("--false-login-sso")
    ap.add_argument("--mimecast")
    ap.add_argument("--gophish", help="non-German GoPhish events")
    ap.add_argument("--o365")
    ap.add_argument("--soc")
    ap.add_argument("--gophish-de", help="German GoPhish events")
    ap.add_argument("--out", default="output")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--write-samples", metavar="DIR", help="dump the selftest fixtures as .xlsx")
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest()
    if a.write_samples:
        return write_samples(a.write_samples)
    if not a.base:
        ap.error("--base is required")

    src = dict(
        base=read_any(a.base, "Employee Email"),
        false_login=read_any(a.false_login) if a.false_login else None,
        false_login_sso=read_any(a.false_login_sso) if a.false_login_sso else None,
        mimecast=read_any(a.mimecast, "To") if a.mimecast else None,
        gophish=read_any(a.gophish, "email") if a.gophish else None,
        o365=read_any(a.o365, "SenderAddress") if a.o365 else None,
        soc=read_any(a.soc, "User") if a.soc else None,
        gophish_de=read_any(a.gophish_de, "email") if a.gophish_de else None,
    )
    print(f"base file: {len(src['base'])} rows")
    final, ger, tabs = run(**src)

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    write_xlsx(out / "Final_Report.xlsx", {"Final Report": final})
    write_xlsx(out / "German_Report.xlsx", {"German Report": ger})
    if tabs:
        write_xlsx(out / "GoPhish_Tabs.xlsx", tabs)

    print(f"\nFinal_Report.xlsx  {len(final)} rows\n{counts(final)}")
    print(f"\nGerman_Report.xlsx {len(ger)} rows\n{counts(ger)}")
    print(f"\nwritten to {out.resolve()}")
    return 0


def fixtures():
    """One synthetic user per rule, each named for the outcome it must end on."""
    def base_row(name, country="India"):
        return {"Employee Name": name, "Country": country,
                "Employee Email": f"{name}@x.com",
                "SSOUPN as per Saviynt": f"{name}@sso.x.com",
                "SSOUPN as per AD (O365)": f"{name}@ad.x.com"}

    names = ["submitted", "clicked", "opened", "userclick", "reported_down",
             "click_wins", "untouched", "de_rule1", "de_rule2", "de_plain"]
    base = pd.DataFrame([base_row(n, "Germany" if n.startswith("de_") else "India") for n in names])

    # 2.1 matches on the Saviynt identity, 2.2 on the AD one - both must work.
    false_login = pd.DataFrame({"Email (SSO)": ["submitted@sso.x.com"]})
    false_login_sso = pd.DataFrame({"Email": ["Clicked <CLICKED@AD.X.COM>"]})
    mimecast = pd.DataFrame({
        "To": ["opened@x.com", "userclick@x.com", "reported_down@x.com", "click_wins@x.com",
               "submitted@x.com", "de_rule1@x.com", "de_rule2@x.com", "de_plain@x.com"],
        "Log Type": ["Email Opened", "User Click", "User Click", "User Click",
                     "Email Opened", "User Click", "User Click", "Email Opened"]})
    gophish = pd.DataFrame({
        "email": ["click_wins@x.com", "userclick@x.com", "penguin@x.com", "droid@x.com"],
        "message": ["Clicked Link", "Email Sent", "Clicked Link", "Clicked Link"],
        "details": ["Windows", "Windows", "Linux", "Linux Android"]})
    o365 = pd.DataFrame({"SenderAddress": ["reported_down@x.com", "click_wins@x.com"]})
    soc = pd.DataFrame({"User": ["de_rule1@x.com"]})
    gophish_de = pd.DataFrame({
        "email": ["de_rule1@x.com", "de_rule2@x.com", "de_plain@x.com"],
        "message": ["Clicked Link", "Submitted Data", "Email Sent"],
        "details": ["Windows", "Windows", "Windows"]})

    return dict(base=base, false_login=false_login, false_login_sso=false_login_sso,
                mimecast=mimecast, gophish=gophish, o365=o365, soc=soc, gophish_de=gophish_de)


def write_samples(out):
    """Dump the selftest fixtures as .xlsx so the UI has something to chew on."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name, frame in fixtures().items():
        write_xlsx(out / f"{name}.xlsx", {name[:31]: frame})
    print(f"sample files written to {out.resolve()}")
    return 0


def selftest():
    final, ger, tabs = run(log=lambda *_: None, **fixtures())
    f = final.set_index("Employee Name")
    g = ger.set_index("Employee Name")

    want = {"submitted": "Submitted Data",    # 2.1 beats the Mimecast "Email Opened"
            "clicked": "Clicked Link",        # 2.2, matched via the AD identity
            "opened": "Email Opened",
            "userclick": "User Click",        # no report, no GoPhish click - stays put
            "reported_down": "Email Opened",  # step 5 rule 1
            "click_wins": "Clicked Link",     # rule 2 overrides rule 1
            "untouched": ""}
    for name, outcome in want.items():
        assert f.loc[name, COL_OUTCOME] == outcome, f"{name}: {f.loc[name, COL_OUTCOME]!r} != {outcome!r}"

    assert list(f[COL_PHISHED]) == [phished(pd.Series([o])).iloc[0] for o in f[COL_OUTCOME]]
    assert f.loc["untouched", COL_PHISHED] == "No"
    assert f.loc["reported_down", COL_REPORTED] == "Yes"
    assert f.loc["userclick", COL_REPORTED] == "No"
    assert f.loc["userclick", COL_GOPHISH] == "Email Sent"
    assert f.loc["click_wins", COL_O365] == COL_O365

    # 3.1: Linux dropped, Linux+Android kept.
    kept = set(tabs["GoPhish Clicked Link"]["email"])
    assert "penguin@x.com" not in kept and "droid@x.com" in kept, kept

    assert list(g.index) == ["de_rule1", "de_rule2", "de_plain"], list(g.index)
    assert g.loc["de_rule1", COL_OUTCOME] == "Email Opened"   # German rule 1, reported
    assert g.loc["de_rule2", COL_OUTCOME] == "Submitted Data"  # German rule 2, takes GoPhish value
    assert g.loc["de_rule2", COL_PHISHED] == "Yes"
    assert g.loc["de_plain", COL_OUTCOME] == "Email Opened"   # never was User Click
    assert g.loc["de_plain", COL_GOPHISH] == "Email Sent"

    print("selftest: all checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
