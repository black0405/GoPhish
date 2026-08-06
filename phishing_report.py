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

try:  # rust xlsx reader: 14s where openpyxl takes 289s on a 36 MB / 200k-row file
    import python_calamine  # noqa: F401
    _XL = {"engine": "calamine"}
    XL_NOTE = "xlsx reads: calamine"
except ImportError:  # still works, just ~20x slower - say so instead of failing silently
    _XL = {}
    XL_NOTE = ("! python_calamine is not installed - xlsx reads fall back to openpyxl, "
               "~20x slower (a 100 MB userbase takes minutes). Fix: pip install python-calamine")

COL_OUTCOME = "Outcome"
COL_GOPHISH = "GoPhish"
COL_O365 = "Reported to O365"
COL_SOC = "Reported to SOC"
COL_REPORTED = "Reported (Yes/No)"
COL_PHISHED = "Phished Yes/No"  # header per "files & column.txt"; steps.txt writes it "Phished (Yes/No)"
NEW_COLS = [COL_OUTCOME, COL_GOPHISH, COL_O365, COL_SOC, COL_REPORTED, COL_PHISHED]

ID_COLS = ["Employee Email", "SSOUPN as per Saviynt", "SSOUPN as per AD (O365)"]
# each outcome step is every ID_COLS x <these> pair - the mapping tables in the SOP
FALSE_LOGIN_COLS = ["Username", "Email (SSO)"]      # 2.1, six pairs -> Submitted Data
FALSE_LOGIN_SSO_COLS = ["Email"]                    # 2.2, three pairs -> Clicked Link
NOT_FOUND = "Not Found"     # what the reporting lookups write when the email matches nobody
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


def dedup(names):
    """pandas-style unique column names: blanks become Unnamed, repeats get .1, .2."""
    out, seen = [], {}
    for i, n in enumerate(names):
        n = n or f"Unnamed: {i}"
        seen[n] = seen.get(n, -1) + 1
        out.append(n if not seen[n] else f"{n}.{seen[n]}")
    return out


def read_any(path, need=None):
    """Read csv/xlsx as text in ONE pass, whatever row the header sits on.

    Exports often carry banner rows above the header. Re-reading the file to
    find it costs a whole extra parse per attempt - minutes on a 100 MB xlsx -
    so the file is parsed headerless once and the header row is picked out of
    the rows already in memory."""
    p = Path(path)
    csv = p.suffix.lower() in (".csv", ".txt")
    raw = (pd.read_csv(p, dtype=str, header=None) if csv
           else pd.read_excel(p, dtype=str, header=None, **_XL))
    if not len(raw):
        return raw
    row = lambda i: ["" if pd.isna(v) else str(v).strip() for v in raw.iloc[i]]
    i = next((j for j in range(min(15, len(raw))) if need in row(j)), 0) if need else 0
    df = raw.iloc[i + 1:].reset_index(drop=True)
    df.columns = dedup(row(i))
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
        """OR over every (base identity column x source column) pair, each pair
        logged with its own count so a mapping table can be checked row by row."""
        m = pd.Series(False, index=base.index)
        for b in (["Employee Email"] if email_only else list(ident)):
            for c in cols:
                if c not in src.columns:
                    continue
                hit = ident[b].isin(set(norm(src[c]).dropna()))
                log(f"    {b} <- {c}: {int(hit.sum())}")
                m |= hit
        return m

    def step(n, name, ok):
        log(f"{'  ' if ok else '- '}{n} {name}" + ("" if ok else " (skipped, no file)"))

    tabs = {}

    # --- Part 1, step 2: outcomes, in the SOP's order. Each check only fills the
    # rows still unresolved - the same as filtering Outcome down to Not Found
    # before applying the next mapping - so a user matched by 2.1 keeps Submitted
    # Data even when 2.2 and 2.3 also name them, and no later check can wipe an
    # outcome an earlier one established. Blank is the unresolved marker while
    # the steps run; it becomes Not Found once they are all done.
    def set_outcome(hit, value):
        unresolved = base[COL_OUTCOME].eq("")
        base.loc[hit & unresolved, COL_OUTCOME] = value
        log(f"    -> {int((hit & unresolved).sum())} set, "
            f"{int((hit & ~unresolved).sum())} already resolved by an earlier check")

    step("2.1", "Submitted Data (false_login)", false_login is not None)
    if false_login is not None:
        set_outcome(matched(false_login, FALSE_LOGIN_COLS), "Submitted Data")

    step("2.2", "Clicked Link (false_login_sso)", false_login_sso is not None)
    if false_login_sso is not None:
        set_outcome(matched(false_login_sso, FALSE_LOGIN_SSO_COLS), "Clicked Link")

    step("2.3", "Mimecast activity", mimecast is not None)
    if mimecast is not None:
        mm = mimecast.copy()
        mm["_k"] = norm(mm["To"])
        mm["_v"] = mm["Log Type"].astype(str).str.strip()
        mm["_r"] = mm["_v"].map(MIMECAST_SEVERITY).fillna(0)
        mm = mm.dropna(subset=["_k"]).sort_values("_r").drop_duplicates("_k", keep="last")
        v = ident["Employee Email"].map(dict(zip(mm["_k"], mm["_v"])))
        unresolved = base[COL_OUTCOME].eq("")
        base.loc[v.notna() & unresolved, COL_OUTCOME] = v[v.notna() & unresolved]
        log(f"    Employee Email <- To: {int(v.notna().sum())}, "
            f"{int((v.notna() & unresolved).sum())} set")

    # Blank means the outcome sources were never supplied; once any of them was,
    # a row nothing matched has been looked up and missed, same as the reporting
    # columns - say Not Found rather than leaving it ambiguous.
    if any(f is not None for f in (mimecast, false_login_sso, false_login)):
        base.loc[base[COL_OUTCOME].eq(""), COL_OUTCOME] = NOT_FOUND

    # --- step 3: GoPhish
    step("3", "GoPhish activity", gophish is not None)
    if gophish is not None:
        g = clean_gophish(gophish)
        log(f"    removed {len(gophish) - len(g)} Linux (non-Android) rows")
        for name, frame in split_events(g, ["Clicked Link", "Email Sent"]).items():
            tabs[f"GoPhish {name}"] = frame
            base.loc[matched(frame, ["email"], email_only=True), COL_GOPHISH] = name

    # --- step 4: reporting. Match on Employee Email; a hit copies the report
    # file's own "reported" value onto the row (e.g. soc-support / o365), a miss
    # writes "Not Found". Blank still means the source file was not supplied.
    def col_of(df, names, idx):
        byname = {str(c).strip().casefold(): c for c in df.columns}
        for n in names:
            if n.casefold() in byname:
                return byname[n.casefold()]
        return df.columns[idx] if idx < len(df.columns) else None

    def lookup(src, col, key_names, key_idx, val_names, val_idx):
        key, val = col_of(src, key_names, key_idx), col_of(src, val_names, val_idx)
        vals = src[val].astype("string").str.strip() if val is not None else pd.Series("", index=src.index)
        vals = vals.where(vals.notna() & vals.ne(""), col)   # matched but blank -> the column name
        against = lambda c: ident["Employee Email"].map(dict(zip(norm(src[c]), vals)))

        m = against(key)
        if not m.notna().any():
            # The named column holds nobody from the userbase. A reported mail
            # lists the phisher as the sender and our employee as the recipient,
            # so the identity is often one column over - use whichever column
            # actually names our people rather than writing Not Found everywhere.
            emails = set(ident["Employee Email"].dropna())
            other = {c: int(norm(src[c]).isin(emails).sum()) for c in src.columns if c != key}
            best = max(other, key=other.get, default=None)
            if best is not None and other[best]:
                log(f"    ! {key} matches nobody in the userbase - using {best} instead"
                    f" ({other[best]} of {len(src)} rows match)")
                key, m = best, against(best)

        base[col] = m.fillna(NOT_FOUND)
        hits = int(m.notna().sum())
        log(f"    matched {key} -> {val}: {hits} updated, {len(base) - hits} {NOT_FOUND.lower()}")

    step("4.1", "Reported to O365", o365 is not None)
    if o365 is not None:
        lookup(o365, COL_O365, ["SenderAddress"], 2, ["Reported"], 10)

    step("4.2", "Reported to SOC", soc is not None)
    if soc is not None:
        lookup(soc, COL_SOC, ["User"], 2, ["reported"], 3)

    hit = lambda col: ~base[col].isin(["", NOT_FOUND])
    base[COL_REPORTED] = (hit(COL_O365) | hit(COL_SOC)).map({True: "Yes", False: "No"})

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
    ap.add_argument("--no-xlsx", action="store_true", help="CSV only - much faster on big files")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--write-samples", metavar="DIR", help="dump the selftest fixtures as .xlsx")
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest()
    if a.write_samples:
        return write_samples(a.write_samples)
    if not a.base:
        ap.error("--base is required")

    print(XL_NOTE)
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
    # .csv costs ~0.4s at 200k rows where .xlsx costs ~30s, so it is always written
    # and the slow one can be turned off while iterating on the rules
    final.to_csv(out / "Final_Report.csv", index=False)
    ger.to_csv(out / "German_Report.csv", index=False)
    if not a.no_xlsx:
        write_xlsx(out / "Final_Report.xlsx", {"Final Report": final})
        write_xlsx(out / "German_Report.xlsx", {"German Report": ger})
        if tabs:
            write_xlsx(out / "GoPhish_Tabs.xlsx", tabs)

    ext = "csv" if a.no_xlsx else "csv + xlsx"
    print(f"\nFinal_Report ({ext})  {len(final)} rows\n{counts(final)}")
    print(f"\nGerman_Report ({ext}) {len(ger)} rows\n{counts(ger)}")
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
    # value columns as in the real exports: O365 column K "Reported", SOC column D "reported"
    o365 = pd.DataFrame({"SenderAddress": ["reported_down@x.com", "click_wins@x.com"],
                         "Reported": ["o365", "o365"]})
    soc = pd.DataFrame({"User": ["de_rule1@x.com"], "reported": ["soc-support"]})
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


def check_read_any():
    """A banner row above the header, a blank header cell and a repeated one."""
    import tempfile
    grid = pd.DataFrame([["User Reported SOC-Support Q2", None, None, None],
                         ["Time", "User", None, "User"],
                         ["09:00", "a@x.com", "x", "b@x.com"]])
    with tempfile.TemporaryDirectory() as d:
        for name in ("probe.xlsx", "probe.csv"):
            p = Path(d) / name
            grid.to_csv(p, index=False, header=False) if name.endswith(".csv") else \
                write_xlsx(p, {"s": grid})
            df = read_any(p, "User")
            assert list(df.columns) == ["Time", "User", "Unnamed: 2", "User.1"], (name, list(df.columns))
            assert len(df) == 1 and df.iloc[0]["User"] == "a@x.com", (name, df.to_dict())
        # no `need` given -> row 0 is the header, as before
        p = Path(d) / "plain.csv"
        pd.DataFrame({"a": [1], "b": [2]}).to_csv(p, index=False)
        assert list(read_any(p).columns) == ["a", "b"]


def check_outcome_pairs():
    """Every mapping in the SOP tables must land on its own, and only the listed
    source columns count - an identity sitting in an unlisted column is a miss."""
    tables = [("false_login", FALSE_LOGIN_COLS, "Submitted Data", "Yes"),
              ("false_login_sso", FALSE_LOGIN_SSO_COLS, "Clicked Link", "Yes")]
    for kw, cols, outcome, phished in tables:
        for bcol in ID_COLS:
            for scol in cols:
                base = pd.DataFrame({"Employee Email": ["hit@x.com", "miss@x.com"],
                                     "SSOUPN as per Saviynt": ["hit@sso.x.com", "miss@sso.x.com"],
                                     "SSOUPN as per AD (O365)": ["hit@ad.x.com", "miss@ad.x.com"]})
                src = pd.DataFrame({c: [base.loc[0, bcol].upper() if c == scol else "other@x.com"]
                                    for c in cols})
                final, _, _ = run(base, log=lambda *_: None, **{kw: src})
                where = f"{kw}: {bcol} <- {scol}"
                assert list(final[COL_OUTCOME]) == [outcome, NOT_FOUND], f"{where}: {list(final[COL_OUTCOME])}"
                assert list(final[COL_PHISHED]) == [phished, "No"], f"{where}: {list(final[COL_PHISHED])}"

        # the same identity in a column the table does not list must not match
        base = pd.DataFrame({"Employee Email": ["hit@x.com"]})
        src = pd.DataFrame({"Some Other Column": ["hit@x.com"], **{c: ["other@x.com"] for c in cols}})
        final, _, _ = run(base, log=lambda *_: None, **{kw: src})
        assert list(final[COL_OUTCOME]) == [NOT_FOUND], f"{kw} matched an unlisted column"

    # each check only fills what is still unresolved, so the earliest one that
    # matches a user wins - 2.1 over 2.2, and both over Mimecast
    base = pd.DataFrame({"Employee Email": ["both@x.com", "clicked@x.com"]})
    both = lambda **kw: run(base, log=lambda *_: None, **kw)[0][COL_OUTCOME].tolist()
    fl = pd.DataFrame({"Username": ["both@x.com"]})
    sso = pd.DataFrame({"Email": ["both@x.com", "clicked@x.com"]})
    mm = pd.DataFrame({"To": ["both@x.com", "clicked@x.com"], "Log Type": ["Email Sent", "Email Sent"]})
    assert both(false_login=fl, false_login_sso=sso) == ["Submitted Data", "Clicked Link"]
    assert both(false_login=fl, false_login_sso=sso, mimecast=mm) == ["Submitted Data", "Clicked Link"]
    assert both(mimecast=mm) == ["Email Sent", "Email Sent"]


def check_lookup_fallback():
    """A real O365 export names the phisher in SenderAddress and our employee in
    RecipientAddress - matching the named column alone would report nobody."""
    base = pd.DataFrame({"Employee Name": ["a", "b"], "Employee Email": ["a@x.com", "b@x.com"]})
    o365 = pd.DataFrame({"MessageId": ["1", "2"],
                         "SenderAddress": ["phisher@evil.com", "phisher@evil.com"],
                         "RecipientAddress": ["a@x.com", "nobody@x.com"],
                         "Reported": ["o365", "o365"]})
    said = []
    final, _, _ = run(base, o365=o365, log=said.append)
    assert list(final[COL_O365]) == ["o365", NOT_FOUND], list(final[COL_O365])
    assert list(final[COL_REPORTED]) == ["Yes", "No"], list(final[COL_REPORTED])
    assert any("using RecipientAddress" in s for s in said), said


def selftest():
    check_read_any()
    check_outcome_pairs()
    check_lookup_fallback()
    final, ger, tabs = run(log=lambda *_: None, **fixtures())
    f = final.set_index("Employee Name")
    g = ger.set_index("Employee Name")

    want = {"submitted": "Submitted Data",    # 2.1 beats the Mimecast "Email Opened"
            "clicked": "Clicked Link",        # 2.2, matched via the AD identity
            "opened": "Email Opened",
            "userclick": "User Click",        # no report, no GoPhish click - stays put
            "reported_down": "Email Opened",  # step 5 rule 1
            "click_wins": "Clicked Link",     # rule 2 overrides rule 1
            "untouched": NOT_FOUND}           # looked up by every outcome source, matched by none
    for name, outcome in want.items():
        assert f.loc[name, COL_OUTCOME] == outcome, f"{name}: {f.loc[name, COL_OUTCOME]!r} != {outcome!r}"

    assert list(f[COL_PHISHED]) == [phished(pd.Series([o])).iloc[0] for o in f[COL_OUTCOME]]
    assert f.loc["untouched", COL_PHISHED] == "No"
    assert f.loc["reported_down", COL_REPORTED] == "Yes"
    assert f.loc["userclick", COL_REPORTED] == "No"
    assert f.loc["userclick", COL_GOPHISH] == "Email Sent"
    # a hit carries the report file's own value; a miss says Not Found
    assert f.loc["click_wins", COL_O365] == "o365", f.loc["click_wins", COL_O365]
    assert f.loc["de_rule1", COL_SOC] == "soc-support", f.loc["de_rule1", COL_SOC]
    assert f.loc["untouched", COL_O365] == NOT_FOUND and f.loc["untouched", COL_SOC] == NOT_FOUND
    assert f.loc["click_wins", COL_SOC] == NOT_FOUND
    assert set(f[COL_O365]) == {"o365", NOT_FOUND}, set(f[COL_O365])

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
