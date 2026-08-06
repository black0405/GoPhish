#!/usr/bin/env python3
"""Phishing report preparation.

The steps built so far, over the whole Userbase file:

    1.1  Reported to O365  SenderAddress (C) -> Reported (K)
    1.2  Reported to SOC   User (C) -> reported (D)
    2.1  Submitted Data    false_login,     Username / Email (SSO)
    2.2  Clicked Link      false_login_sso, Email
    3    Mimecast          To (C) -> Log Type (O)
    4.1  GoPhish           email (B) -> message (D), Linux rows excluded first
    4.2  GoPhish German    the same split, filling in Submitted Data, Clicked
                           Link, Email Sent order over what 4.1 left
    5    Reconcile         Outcome User Click + Reported Yes -> Email Opened
    6    Germany           Country = Germany and Outcome still Not Found or
                           User Click -> take that row's GoPhish value
    7    Everywhere else   the same rows outside Germany -> Email Sent

Steps 2 and 3 share one Outcome column and step 4 fills GoPhish; in both, each
check only fills rows no earlier one resolved. The reconcile pass and the German
part are not built yet - see git history for the earlier drafts.

    python phishing_report.py --base UserBase_V2.xlsx \
        --false-login "False_login_data-Q2-Submitted.xlsx" \
        --false-login-sso "false_login_sso_data-Q2-Clicked Link.xlsx" \
        --mimecast mimecast_combine.xlsx \
        --o365 "User Reported-Microsoft 365Report button.xlsx" \
        --soc "User Reported SOC-Support.xlsx" \
        --gophish GoPhish_Events_non_german.xlsx \
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
MIMECAST_SEVERITY = {"Email Sent": 0, "Email Opened": 1, "User Click": 2}
GOPHISH_EVENTS = ["Clicked Link", "Email Sent"]                       # 4.1 sheets and fill order
GOPHISH_DE_EVENTS = ["Clicked Link", "Email Sent", "Submitted Data"]  # 4.2 sheet order
GOPHISH_DE_FILL = ["Submitted Data", "Clicked Link", "Email Sent"]    # 4.2 fill order
GOPHISH_DEFAULT = "Email Sent"   # what GoPhish reads when neither file named the user
SHEET_EXCLUDED = "excluded linux"
# each GoPhish file becomes its own workbook, so the two download separately
BOOK_GOPHISH, BOOK_GOPHISH_DE = "GoPhish_non_german", "GoPhish_german"
# details sits in a different column in the two exports: E in the non-German
# file (campaign_id, email, time, message, details), F in the German one, which
# has a Sort column before it. Both are found by name first.
GOPHISH_DETAILS_IDX, GOPHISH_DE_DETAILS_IDX = 4, 5


def gophish_split(g, events, details_idx, log):
    """The Linux (non-Android) rows move out to their own sheet and take no
    further part; what is left is split into one sheet per event value. The
    sheets become their own workbook, one per GoPhish file.

    Returns ({sheet name: frame}, {event: frame}, email column, message series)."""
    em = col_of(g, ["email"], 1)
    msg = col_of(g, ["message"], 3)
    det = col_of(g, ["details"], details_idx)

    d = g[det].astype(str) if det is not None else pd.Series("", index=g.index)
    linux = d.str.contains("linux", case=False, na=False) & ~d.str.contains("android", case=False, na=False)
    kept = g[~linux]
    log(f"    {det} contains linux, not android: {int(linux.sum())} rows moved to "
        f"'{SHEET_EXCLUDED}', {len(kept)} rows left")

    # the untouched export leads the workbook, so it shows what was split and
    # what it was split from
    sheets = {"gophish data": g.copy(), SHEET_EXCLUDED: g[linux].copy()}
    message = kept[msg].astype("string").str.strip()
    frames = {}
    for event in events:
        frames[event] = kept[message.str.casefold() == event.casefold()]
        sheets[event.lower()] = frames[event].copy()
        log(f"    '{event.lower()}' sheet: {len(frames[event])} rows")
    return sheets, frames, em, message


def norm(s):
    """Normalise an identity column to a bare lowercase email where possible."""
    s = s.astype("string").str.strip().str.strip("\"'<>").str.lower()
    s = s.str.replace(r"^mailto:", "", regex=True)
    out = s.str.extract(r"([^\s<>,;]+@[^\s<>,;]+)", expand=False).fillna(s)
    return out.replace({"": pd.NA})


def canon_log_type(s, log=print):
    """Mimecast's Log Type goes into Outcome as-is, and later steps compare that
    text exactly ("User Click"), so a row spelled "user click" or with a double
    space would silently never match. Recognised values are rewritten to the
    spelling MIMECAST_SEVERITY uses; anything else is passed through and named."""
    # \s does not cover the non-breaking space under every pandas string backend,
    # and Excel exports are full of them, so replace it by hand before collapsing
    s = s.astype("string").str.replace(" ", " ", regex=False)
    s = s.str.replace(r"\s+", " ", regex=True).str.strip()
    # compare with the spaces taken out entirely, so "UserClick" matches too
    known = {"".join(k.split()).casefold(): k for k in MIMECAST_SEVERITY}
    out = s.str.replace(" ", "", regex=False).str.casefold().map(known)
    odd = s[out.isna() & s.notna() & s.ne("")]
    if len(odd):
        shown = ", ".join(f"{v!r} ({n})" for v, n in odd.value_counts().head(5).items())
        log(f"    ! Log Type values not recognised, passed through as-is: {shown}")
    return out.fillna(s)


def col_of(df, names, idx):
    """A column by header name, falling back to its spreadsheet position."""
    byname = {str(c).strip().casefold(): c for c in df.columns}
    for n in names:
        if n.casefold() in byname:
            return byname[n.casefold()]
    return df.columns[idx] if idx < len(df.columns) else None


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


def run(base, false_login=None, false_login_sso=None, mimecast=None,
        o365=None, soc=None, gophish=None, gophish_de=None, log=print):
    """Returns (report frame, {workbook stem: {sheet name: frame}}) - the report
    is the userbase with NEW_COLS filled in, and each GoPhish file supplied gets
    a workbook of its own holding step 4's split of it."""
    base = base.copy()
    books = {}
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

    def matched(src, cols):
        """OR over every (base identity column x source column) pair, each pair
        logged with its own count so a mapping table can be checked row by row."""
        m = pd.Series(False, index=base.index)
        for b in ident:
            for c in cols:
                if c not in src.columns:
                    continue
                hit = ident[b].isin(set(norm(src[c]).dropna()))
                log(f"    {b} <- {c}: {int(hit.sum())}")
                m |= hit
        return m

    def step(n, name, ok):
        log(f"{'  ' if ok else '- '}{n} {name}" + ("" if ok else " (skipped, no file)"))

    # --- step 1: reporting. Match on Employee Email; a hit copies the report
    # file's own "reported" value onto the row (e.g. soc-support / o365), a miss
    # writes "Not Found". Blank still means the source file was not supplied.
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

    step("1.1", "Reported to O365", o365 is not None)
    if o365 is not None:
        lookup(o365, COL_O365, ["SenderAddress"], 2, ["Reported"], 10)

    step("1.2", "Reported to SOC", soc is not None)
    if soc is not None:
        lookup(soc, COL_SOC, ["User"], 2, ["reported"], 3)

    hit_col = lambda col: ~base[col].isin(["", NOT_FOUND])
    base[COL_REPORTED] = (hit_col(COL_O365) | hit_col(COL_SOC)).map({True: "Yes", False: "No"})

    # --- steps 2 and 3: outcomes. Each check only fills the rows still
    # unresolved - the same as filtering Outcome down to Not Found before
    # applying the next mapping - so a user matched by 2.1 keeps Submitted Data
    # even when 2.2 and 3 also name them, and no later check can wipe an outcome
    # an earlier one established. Blank is the unresolved marker while the steps
    # run; it becomes Not Found once they are all done.
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

    # step 3: Employee Email against To (column C), taking Log Type (column O).
    step("3", "Mimecast activity", mimecast is not None)
    if mimecast is not None:
        key, val = col_of(mimecast, ["To"], 2), col_of(mimecast, ["Log Type"], 14)
        k, v = norm(mimecast[key]), canon_log_type(mimecast[val], log)
        # a user usually has several Mimecast rows (sent, then opened, then
        # clicked); keep the furthest they got rather than whichever sorted last
        mm = pd.DataFrame({"_k": k, "_v": v, "_r": v.map(MIMECAST_SEVERITY).fillna(0)})
        mm = mm.dropna(subset=["_k"]).sort_values("_r").drop_duplicates("_k", keep="last")
        hit = ident["Employee Email"].map(dict(zip(mm["_k"], mm["_v"])))
        unresolved = base[COL_OUTCOME].eq("")
        base.loc[hit.notna() & unresolved, COL_OUTCOME] = hit[hit.notna() & unresolved]
        log(f"    Employee Email <- {key} -> {val}: {int(hit.notna().sum())} matched")
        log(f"    -> {int((hit.notna() & unresolved).sum())} set, "
            f"{int((hit.notna() & ~unresolved).sum())} already resolved by an earlier check")

    # Blank means the outcome sources were never supplied; once any of them was,
    # a row nothing matched has been looked up and missed, same as the reporting
    # columns - say Not Found rather than leaving it ambiguous.
    if any(f is not None for f in (mimecast, false_login_sso, false_login)):
        base.loc[base[COL_OUTCOME].eq(""), COL_OUTCOME] = NOT_FOUND

    # --- step 4: GoPhish. The events file is split into sheets first - the Linux
    # (non-Android) rows are moved out entirely, then one sheet per event - and
    # the GoPhish column is filled from those sheets in GOPHISH_EVENTS order,
    # each pass only filling rows the pass before it left unresolved.
    def fill_gophish(frames, order, em, message):
        """Each sheet in turn, filling only the rows still unresolved - the same
        filter-to-Not-Found-then-map shape the Outcome steps use. The value
        written is the sheet's own message, not a constant."""
        for event in order:
            frame = frames[event]
            hit = ident["Employee Email"].map(dict(zip(norm(frame[em]), message[frame.index])))
            unresolved = base[COL_GOPHISH].eq("")
            base.loc[hit.notna() & unresolved, COL_GOPHISH] = hit[hit.notna() & unresolved]
            log(f"    '{event.lower()}' -> Employee Email <- {em}: {int(hit.notna().sum())} matched")
            log(f"    -> {int((hit.notna() & unresolved).sum())} set, "
                f"{int((hit.notna() & ~unresolved).sum())} already resolved by an earlier sheet")

    step("4.1", "GoPhish activity (non-German)", gophish is not None)
    if gophish is not None:
        books[BOOK_GOPHISH], frames, em, message = gophish_split(
            gophish, GOPHISH_EVENTS, GOPHISH_DETAILS_IDX, log)
        fill_gophish(frames, GOPHISH_EVENTS, em, message)

    # 4.2: the German file is split the same way but into four sheets, and fills
    # in a different order - Submitted Data first, then Clicked Link, then Email
    # Sent - over the rows 4.1 left unresolved.
    step("4.2", "GoPhish activity (German)", gophish_de is not None)
    if gophish_de is not None:
        books[BOOK_GOPHISH_DE], frames, em, message = gophish_split(
            gophish_de, GOPHISH_DE_EVENTS, GOPHISH_DE_DETAILS_IDX, log)
        fill_gophish(frames, GOPHISH_DE_FILL, em, message)

    # Blank is the unresolved marker while 4.1 and 4.2 run. Whoever neither file
    # named still received the mail, so the leftovers read Email Sent rather than
    # Not Found - including anyone whose only events were Linux rows that 4.1 or
    # 4.2 excluded.
    if gophish is not None or gophish_de is not None:
        rest = base[COL_GOPHISH].eq("")
        base.loc[rest, COL_GOPHISH] = GOPHISH_DEFAULT
        log(f"    {int(rest.sum())} rows matched by neither file -> {GOPHISH_DEFAULT}")

    # --- step 5: a Mimecast User Click from someone who reported the mail was
    # them clicking the report button, not the phish. Runs last: it needs the
    # Outcome from steps 2-3 and Reported (Yes/No) from step 1.
    log("  5   reconcile Outcome")
    click = base[COL_OUTCOME].eq("User Click")
    yes = base[COL_REPORTED].eq("Yes")
    fix = click & yes
    base.loc[fix, COL_OUTCOME] = "Email Opened"
    # both counts, so a zero result says which half of the rule was empty
    log(f"    User Click: {int(click.sum())}, Reported Yes: {int(yes.sum())}, "
        f"both -> Email Opened: {int(fix.sum())}")
    # and what the reported rows actually say, quoted, so a value that only looks
    # like "User Click" is visible rather than leaving the rule looking broken
    seen = base.loc[yes, COL_OUTCOME].value_counts().head(8)
    if len(seen):
        log("    Outcome on the Reported Yes rows: "
            + ", ".join(f"{v!r} ({n})" for v, n in seen.items()))

    # --- step 6: for Germany only, an Outcome still reading Not Found or User
    # Click is replaced by that row's GoPhish value. Any other Outcome stands -
    # a German user with Submitted Data keeps it.
    log("  6   German rows take the GoPhish value")
    # By name only. The generated columns are appended to the base, so a
    # positional fallback here could land on one of those rather than column B.
    country = next((c for c in base.columns if str(c).strip().casefold() == "country"), None)
    unsettled = lambda: base[COL_OUTCOME].isin([NOT_FOUND, "User Click"])
    if country is None:
        log("    ! base file has no Country column - steps 6 and 7 skipped")
    else:
        de = base[country].astype(str).str.strip().str.casefold().eq("germany")
        take = de & unsettled() & ~base[COL_GOPHISH].isin(["", NOT_FOUND])
        base.loc[take, COL_OUTCOME] = base.loc[take, COL_GOPHISH]
        log(f"    {country} = Germany: {int(de.sum())} rows, "
            f"{int(take.sum())} taking their GoPhish value into Outcome")

        # --- step 7: everywhere except Germany, an Outcome still reading Not
        # Found or User Click becomes Email Sent. Same filter as step 6, the
        # other side of the country split; a settled Outcome is left alone.
        log("  7   everywhere but Germany -> Email Sent")
        rest = ~de & unsettled()
        base.loc[rest, COL_OUTCOME] = "Email Sent"
        log(f"    {country} not Germany: {int((~de).sum())} rows, "
            f"{int(rest.sum())} set to Email Sent")

    # Phished Yes/No is left empty on purpose - the rule for it has not been
    # specified, so the column ships blank rather than guessed at.
    return base, books


def write_xlsx(path, sheets):
    with pd.ExcelWriter(path, engine="openpyxl") as w:
        for name, frame in sheets.items():
            frame.to_excel(w, sheet_name=name[:31], index=False)


def counts(df):
    if not len(df):
        return "  (empty)"
    o = df[COL_OUTCOME].replace("", "(blank)").value_counts()
    g = df[COL_GOPHISH].replace("", "(blank)").value_counts()
    return ("  Outcome: " + ", ".join(f"{k}={v}" for k, v in o.items()) +
            "\n  GoPhish: " + ", ".join(f"{k}={v}" for k, v in g.items()))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", help="Userbase file")
    ap.add_argument("--false-login")
    ap.add_argument("--false-login-sso")
    ap.add_argument("--mimecast")
    ap.add_argument("--o365")
    ap.add_argument("--soc")
    ap.add_argument("--gophish", help="non-German GoPhish events")
    ap.add_argument("--gophish-de", help="German GoPhish events (sheets only)")
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
        o365=read_any(a.o365, "SenderAddress") if a.o365 else None,
        soc=read_any(a.soc, "User") if a.soc else None,
        gophish=read_any(a.gophish, "email") if a.gophish else None,
        gophish_de=read_any(a.gophish_de, "email") if a.gophish_de else None,
    )
    print(f"base file: {len(src['base'])} rows")
    final, books = run(**src)

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    # .csv costs ~0.4s at 200k rows where .xlsx costs ~30s, so it is always written
    # and the slow one can be turned off while iterating on the rules
    final.to_csv(out / "Final_Report.csv", index=False)
    if not a.no_xlsx:
        write_xlsx(out / "Final_Report.xlsx", {"Final Report": final})
    # the GoPhish workbooks are small and are always written, one per file
    for stem, sheets in books.items():
        write_xlsx(out / f"{stem}.xlsx", sheets)
        print(f"{stem}.xlsx: " + ", ".join(f"{n} ({len(f)})" for n, f in sheets.items()))

    ext = "csv" if a.no_xlsx else "csv + xlsx"
    print(f"\nFinal_Report ({ext})  {len(final)} rows\n{counts(final)}")
    print(f"\nwritten to {out.resolve()}")
    return 0


def fixtures():
    """One synthetic user per rule, each named for the outcome it must end on."""
    def base_row(name, country="India"):
        return {"Employee Name": name, "Country": country,
                "Employee Email": f"{name}@x.com",
                "SSOUPN as per Saviynt": f"{name}@sso.x.com",
                "SSOUPN as per AD (O365)": f"{name}@ad.x.com"}

    names = ["submitted", "clicked", "opened", "escalated", "reported", "untouched",
             "clickreported", "de_sub", "de_click", "de_sent", "de_both", "de_excluded",
             "de_keep"]
    base = pd.DataFrame([base_row(n, "Germany" if n.startswith("de_") else "India") for n in names])

    # 2.1 matches on the Saviynt identity, 2.2 on the AD one - both must work.
    # de_keep already has an Outcome, so step 6 must leave it alone
    false_login = pd.DataFrame({"Email (SSO)": ["submitted@sso.x.com", "de_keep@sso.x.com"]})
    false_login_sso = pd.DataFrame({"Email": ["Clicked <CLICKED@AD.X.COM>"]})
    # "submitted" is here too and must keep Submitted Data; "escalated" has three
    # rows and must end on the furthest of them
    mimecast = pd.DataFrame({
        "To": ["opened@x.com", "submitted@x.com", "clickreported@x.com", "de_click@x.com",
               "escalated@x.com", "escalated@x.com", "escalated@x.com"],
        "Log Type": ["Email Opened", "Email Opened", "User Click", "User Click",
                     "Email Sent", "User Click", "Email Opened"]})
    # value columns as in the real exports: O365 column K "Reported", SOC column D "reported"
    o365 = pd.DataFrame({"SenderAddress": ["reported@x.com", "clickreported@x.com"],
                         "Reported": ["o365", "o365"]})
    soc = pd.DataFrame({"User": ["reported@x.com"], "reported": ["soc-support"]})
    # "clicked" is in both event sheets and must take the Clicked Link pass;
    # "penguin" is Linux without Android and must be excluded before any mapping
    # column order per "files & column.txt": no Sort column in the non-German file
    gophish = pd.DataFrame({
        "campaign_id": ["1"] * 5,
        "email": ["clicked@x.com", "clicked@x.com", "opened@x.com", "escalated@x.com", "untouched@x.com"],
        "time": ["09:00"] * 5,
        "message": ["Clicked Link", "Email Sent", "Email Sent", "Clicked Link", "Clicked Link"],
        "details": ["Windows", "Windows", "Linux Android", "Windows", "Linux x86_64"]})
    # the German export has a Sort column, so details lands one column further
    # right. "de_both" is in two sheets and must take Submitted Data, which
    # fills first here; "de_excluded" is Linux without Android.
    gophish_de = pd.DataFrame({
        "campaign_id": ["2"] * 6,
        "email": ["de_click@x.com", "de_sent@x.com", "de_sub@x.com",
                  "de_both@x.com", "de_both@x.com", "de_excluded@x.com"],
        "time": ["09:00"] * 6,
        "message": ["Clicked Link", "Email Sent", "Submitted Data",
                    "Clicked Link", "Submitted Data", "Submitted Data"],
        "Sort": [""] * 6,
        "details": ["Windows", "Linux Android", "Windows",
                    "Windows", "Windows", "Linux x86_64"]})

    return dict(base=base, false_login=false_login, false_login_sso=false_login_sso,
                mimecast=mimecast, o365=o365, soc=soc, gophish=gophish, gophish_de=gophish_de)


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
    tables = [("false_login", FALSE_LOGIN_COLS, "Submitted Data"),
              ("false_login_sso", FALSE_LOGIN_SSO_COLS, "Clicked Link")]
    for kw, cols, outcome in tables:
        for bcol in ID_COLS:
            for scol in cols:
                base = pd.DataFrame({"Employee Email": ["hit@x.com", "miss@x.com"],
                                     "SSOUPN as per Saviynt": ["hit@sso.x.com", "miss@sso.x.com"],
                                     "SSOUPN as per AD (O365)": ["hit@ad.x.com", "miss@ad.x.com"]})
                src = pd.DataFrame({c: [base.loc[0, bcol].upper() if c == scol else "other@x.com"]
                                    for c in cols})
                final, _ = run(base, log=lambda *_: None, **{kw: src})
                where = f"{kw}: {bcol} <- {scol}"
                assert list(final[COL_OUTCOME]) == [outcome, NOT_FOUND], f"{where}: {list(final[COL_OUTCOME])}"

        # the same identity in a column the table does not list must not match
        base = pd.DataFrame({"Employee Email": ["hit@x.com"]})
        src = pd.DataFrame({"Some Other Column": ["hit@x.com"], **{c: ["other@x.com"] for c in cols}})
        final, _ = run(base, log=lambda *_: None, **{kw: src})
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


def check_gophish_file_order():
    """4.1 runs before 4.2, so a user named by both files keeps the non-German
    value even when the German file would have given a different one."""
    base = pd.DataFrame({"Employee Email": ["both@x.com", "de_only@x.com"]})
    cols = ["campaign_id", "email", "time", "message", "details"]
    non_de = pd.DataFrame([["1", "both@x.com", "09:00", "Email Sent", "Windows"]], columns=cols)
    de = pd.DataFrame([["2", "both@x.com", "09:00", "Submitted Data", "", "Windows"],
                       ["2", "de_only@x.com", "09:00", "Submitted Data", "", "Windows"]],
                      columns=cols[:4] + ["Sort", "details"])
    final, _ = run(base, gophish=non_de, gophish_de=de, log=lambda *_: None)
    assert list(final[COL_GOPHISH]) == ["Email Sent", "Submitted Data"], list(final[COL_GOPHISH])


def check_lookup_fallback():
    """A real O365 export names the phisher in SenderAddress and our employee in
    RecipientAddress - matching the named column alone would report nobody."""
    base = pd.DataFrame({"Employee Name": ["a", "b"], "Employee Email": ["a@x.com", "b@x.com"]})
    o365 = pd.DataFrame({"MessageId": ["1", "2"],
                         "SenderAddress": ["phisher@evil.com", "phisher@evil.com"],
                         "RecipientAddress": ["a@x.com", "nobody@x.com"],
                         "Reported": ["o365", "o365"]})
    said = []
    final, _ = run(base, o365=o365, log=said.append)
    assert list(final[COL_O365]) == ["o365", NOT_FOUND], list(final[COL_O365])
    assert list(final[COL_REPORTED]) == ["Yes", "No"], list(final[COL_REPORTED])
    assert any("using RecipientAddress" in s for s in said), said


def check_step5_spelling():
    """Mimecast writes Outcome, so step 5 must fire whatever case or spacing the
    export uses for User Click."""
    base = pd.DataFrame({"Employee Email": ["a@x.com", "b@x.com", "c@x.com", "d@x.com"]})
    mm = pd.DataFrame({"To": ["a@x.com", "b@x.com", "c@x.com", "d@x.com"],
                       "Log Type": ["User Click", "user  click", "User Click", "USERCLICK"]})
    o365 = pd.DataFrame({"SenderAddress": ["a@x.com", "b@x.com", "c@x.com"],
                         "Reported": ["o365"] * 3})
    mm["Log Type"] = ["User Click", "user  click", "User Click", "USERCLICK"]
    final, _ = run(base, mimecast=mm, o365=o365, log=lambda *_: None)
    # every spelling counts as a click - case, doubled space, non-breaking space,
    # no space at all. The fourth did not report it, so it stays a click.
    assert list(final[COL_OUTCOME]) == ["Email Opened"] * 3 + ["User Click"], list(final[COL_OUTCOME])

    # a base with no Country column must not fall back onto a generated one
    said = []
    run(pd.DataFrame({"Employee Email": ["a@x.com"]}), mimecast=mm, log=said.append)
    assert any("no Country column" in s for s in said), said


def check_mimecast_columns():
    """2.3 finds To and Log Type by position (C and O) when the headers differ."""
    base = pd.DataFrame({"Employee Email": ["a@x.com"]})
    wide = {chr(65 + i): [""] for i in range(15)}       # 15 columns, A..O
    wide["C"], wide["O"] = ["A@X.COM"], ["User Click"]  # position 2 and 14
    final, _ = run(base, mimecast=pd.DataFrame(wide), log=lambda *_: None)
    assert list(final[COL_OUTCOME]) == ["User Click"], list(final[COL_OUTCOME])


def selftest():
    check_read_any()
    check_outcome_pairs()
    check_lookup_fallback()
    check_mimecast_columns()
    check_step5_spelling()
    check_gophish_file_order()
    final, books = run(log=lambda *_: None, **fixtures())
    f = final.set_index("Employee Name")

    want = {"submitted": "Submitted Data",  # 2.1 keeps it; Mimecast may not overwrite
            "clicked": "Clicked Link",      # 2.2, matched via the AD identity
            "opened": "Email Opened",
            # step 7: outside Germany, a leftover User Click or Not Found -> Email Sent
            "escalated": "Email Sent",      # was User Click, nobody reported it
            "clickreported": "Email Opened",  # step 5 settled it before step 7 could
            "reported": "Email Sent",       # was Not Found
            "untouched": "Email Sent",      # was Not Found
            # step 6: Germany, Not Found or User Click, takes its GoPhish value
            "de_sub": "Submitted Data",
            "de_click": "Clicked Link",     # was User Click from Mimecast
            "de_sent": "Email Sent",
            "de_both": "Submitted Data",
            "de_excluded": "Email Sent",    # GoPhish fell back to Email Sent
            "de_keep": "Submitted Data"}    # already had an Outcome, step 6 leaves it
    for name, outcome in want.items():
        assert f.loc[name, COL_OUTCOME] == outcome, f"{name}: {f.loc[name, COL_OUTCOME]!r} != {outcome!r}"

    assert set(f[COL_PHISHED]) == {""}, "Phished Yes/No is not specified yet - it must stay empty"
    assert f.loc["reported", COL_REPORTED] == "Yes"
    assert f.loc["opened", COL_REPORTED] == "No"
    # a hit carries the report file's own value; a miss says Not Found
    assert f.loc["reported", COL_O365] == "o365", f.loc["reported", COL_O365]
    assert f.loc["reported", COL_SOC] == "soc-support", f.loc["reported", COL_SOC]
    assert f.loc["untouched", COL_O365] == NOT_FOUND and f.loc["untouched", COL_SOC] == NOT_FOUND
    assert set(f[COL_O365]) == {"o365", NOT_FOUND}, set(f[COL_O365])
    # step 5 only touches User Click rows that were reported
    assert f.loc["clickreported", COL_REPORTED] == "Yes"
    assert f.loc["escalated", COL_REPORTED] == "No", "a User Click nobody reported must stay put"

    # step 4: the Linux (non-Android) row is moved out and never mapped, the
    # Clicked Link pass runs before Email Sent, the rest say Not Found
    # one workbook per GoPhish file, each led by the untouched export
    assert list(books) == [BOOK_GOPHISH, BOOK_GOPHISH_DE], list(books)
    assert list(books[BOOK_GOPHISH]) == ["gophish data", SHEET_EXCLUDED,
                                         "clicked link", "email sent"], list(books[BOOK_GOPHISH])
    assert list(books[BOOK_GOPHISH_DE]) == ["gophish data", SHEET_EXCLUDED, "clicked link",
                                            "email sent", "submitted data"], list(books[BOOK_GOPHISH_DE])
    assert books[BOOK_GOPHISH]["gophish data"].equals(fixtures()["gophish"])
    assert books[BOOK_GOPHISH_DE]["gophish data"].equals(fixtures()["gophish_de"])
    # every row of each export lands in exactly one of that workbook's other sheets
    for book, src in ((BOOK_GOPHISH, "gophish"), (BOOK_GOPHISH_DE, "gophish_de")):
        parts = sum(len(f) for n, f in books[book].items() if n != "gophish data")
        assert parts == len(fixtures()[src]), f"{book}: {parts} != {len(fixtures()[src])}"
        # the sheets are the export's own columns; the mapping belongs to the
        # report, so no workbook sheet may carry a GoPhish column of its own
        for name, frame in books[book].items():
            assert list(frame.columns) == list(fixtures()[src].columns), f"{book}/{name}"
            assert COL_GOPHISH not in frame.columns, f"{book}/{name} has a {COL_GOPHISH} column"

    # 4.2 - details is column F there, so the Linux row must still be found, and
    # the fill order is Submitted Data, then Clicked Link, then Email Sent
    de = books[BOOK_GOPHISH_DE]
    assert list(de[SHEET_EXCLUDED]["email"]) == ["de_excluded@x.com"]
    assert list(de["clicked link"]["email"]) == ["de_click@x.com", "de_both@x.com"]
    assert list(de["email sent"]["email"]) == ["de_sent@x.com"]   # Linux Android, kept
    assert list(de["submitted data"]["email"]) == ["de_sub@x.com", "de_both@x.com"]

    sheets = books[BOOK_GOPHISH]
    assert list(sheets[SHEET_EXCLUDED]["email"]) == ["untouched@x.com"], sheets[SHEET_EXCLUDED]
    assert list(sheets["clicked link"]["email"]) == ["clicked@x.com", "escalated@x.com"]
    assert list(sheets["email sent"]["email"]) == ["clicked@x.com", "opened@x.com"]
    # whoever neither file named falls through to Email Sent, never Not Found
    want_gp = {"clicked": "Clicked Link",     # in both sheets, Clicked Link runs first
               "escalated": "Clicked Link",
               "opened": "Email Sent",
               "untouched": GOPHISH_DEFAULT,  # its only row was excluded as Linux
               "submitted": GOPHISH_DEFAULT, "reported": GOPHISH_DEFAULT,
               "de_sub": "Submitted Data",    # German, filled by 4.2
               "de_click": "Clicked Link",
               "de_sent": "Email Sent",
               "de_both": "Submitted Data",   # in two German sheets, this one fills first
               "de_excluded": GOPHISH_DEFAULT,  # its rows were excluded as Linux
               "de_keep": GOPHISH_DEFAULT}    # neither file names them
    assert NOT_FOUND not in set(f[COL_GOPHISH]), set(f[COL_GOPHISH])
    # steps 6 and 7 between them settle every row, so Outcome has no leftovers
    assert NOT_FOUND not in set(f[COL_OUTCOME]), set(f[COL_OUTCOME])
    assert "User Click" not in set(f[COL_OUTCOME]), set(f[COL_OUTCOME])
    for name, value in want_gp.items():
        assert f.loc[name, COL_GOPHISH] == value, f"{name}: {f.loc[name, COL_GOPHISH]!r} != {value!r}"

    print("selftest: all checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
