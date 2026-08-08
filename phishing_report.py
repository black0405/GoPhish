#!/usr/bin/env python3
"""Phishing report preparation.

The steps built so far, over the whole Userbase file:

    1.1  Reported to O365  SenderAddress (C) -> Reported (K)
    1.2  Reported to SOC   User (C) -> reported (D)
    2.1  false_login       Username / Email (SSO) (D, E) -> its Outcome (G)
    2.2  false_login_sso   Email (D) -> its Outcome (G)
    3    Mimecast          To (C) -> Log Type (N), first row per user, only
                           rows step 2 left empty
    4.1  GoPhish           email (B) -> message (D) into the GoPhish column
                           ONLY, Linux rows excluded first; clicked link sheet,
                           then email sent, leftovers Not Found
    4.2  GoPhish German    the same split, filling Submitted Data, Clicked
                           Link, Email Sent order over what 4.1 left; GoPhish
                           column only, no country filter anywhere
    5    Submitted         leftover (Not Found / User Click) whose GoPhish says
                           Submitted Data takes it - beats the reported lift
    6    Reported          Reported Yes + (leftover or Clicked Link) -> Email
                           Opened; only Submitted Data survives a report
    7    Leftovers         the rest take their GoPhish value, any country;
                           whoever has none -> Email Sent
    8    Phished Yes/No    Yes for Submitted Data and Clicked Link, No otherwise

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
PHISHED_YES = {"Submitted Data", "Clicked Link"}   # step 8: the outcomes that count as phished
MIMECAST_SEVERITY = {"Email Sent": 0, "Email Opened": 1, "User Click": 2}
GOPHISH_EVENTS = ["Clicked Link", "Email Sent"]                       # 4.1 sheets and fill order
GOPHISH_DE_EVENTS = ["Clicked Link", "Email Sent", "Submitted Data"]  # 4.2 sheet order
GOPHISH_DE_FILL = ["Submitted Data", "Clicked Link", "Email Sent"]    # 4.2 fill order
GOPHISH_DEFAULT = "Email Sent"   # the one event that never fills Outcome (delivery only)
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
    """A column by header name, falling back to its spreadsheet position.
    Header whitespace is collapsed (exports love a non-breaking space or a
    doubled one inside 'Log Type')."""
    clean = lambda s: re.sub(r"\s+", " ", str(s).replace("\xa0", " ")).strip().casefold()
    byname = {clean(c): c for c in df.columns}
    for n in names:
        if clean(n) in byname:
            return byname[clean(n)]
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
        o365=None, soc=None, gophish=None, gophish_de=None, log=print, snap=None):
    """Returns (report frame, {workbook stem: {sheet name: frame}}) - the report
    is the userbase with NEW_COLS filled in, and each GoPhish file supplied gets
    a workbook of its own holding step 4's split of it.

    `snap(name, frame)`, when given, is called with the report as it stands
    after each step, so the caller can save per-step files for checking."""
    snap = snap or (lambda *_: None)
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

    def step(n, name, ok):
        log(f"{'  ' if ok else '- '}{n} {name}" + ("" if ok else " (skipped, no file)"))

    # --- step 1: reporting. Match on Employee Email; a hit copies the report
    # file's own "reported" value onto the row (e.g. soc-support / o365), a miss
    # writes "Not Found". Blank still means the source file was not supplied.
    def lookup(src, col, key_names, key_idx, val_names, val_idx):
        key, val = col_of(src, key_names, key_idx), col_of(src, val_names, val_idx)
        vals = src[val].astype("string").str.strip() if val is not None else pd.Series("", index=src.index)
        vals = vals.where(vals.notna() & vals.ne(""), col)   # matched but blank -> the column name

        def against(c):
            k = norm(src[c])
            ok = k.notna()
            # XLOOKUP semantics: the first row for a user wins
            return ident["Employee Email"].map(dict(zip(k[ok][::-1], vals[ok][::-1])))

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
    snap("Step1_Reporting", base)

    # --- step 2: false logins, XLOOKUP-style. For each (base identity x source
    # column) pair IN ORDER - S->D, S->E, AD->D, AD->E, AG->D, AG->E - a hit
    # copies that row's own Outcome value (column G). Each later pair fills only
    # the rows still empty, and within one column the FIRST row for a user wins,
    # as XLOOKUP does. A hit whose Outcome cell is blank leaves the row empty,
    # so a later pair can still fill it. Blank is the unresolved marker while
    # the steps run; it becomes Not Found once they are all done.
    def outcome_fill(src, cols, default):
        out_col = col_of(src, ["Outcome"], 6)
        vals = (src[out_col].astype("string").str.strip() if out_col is not None
                else pd.Series(default, index=src.index))
        for b in ident:            # ident keeps ID_COLS order: S, then AD, then AG
            for c in cols:
                if c not in src.columns:
                    continue
                k = norm(src[c])
                ok = k.notna()
                first = dict(zip(k[ok][::-1], vals[ok][::-1]))   # reversed -> first row wins
                hit = ident[b].map(first)
                fill = hit.notna() & hit.ne("") & base[COL_OUTCOME].eq("")
                base.loc[fill, COL_OUTCOME] = hit[fill]
                log(f"    {b} <- {c}: {int(hit.notna().sum())} matched, {int(fill.sum())} set")

    step("2.1", "false_login (Outcome from its column G)", false_login is not None)
    if false_login is not None:
        outcome_fill(false_login, FALSE_LOGIN_COLS, "Submitted Data")

    step("2.2", "false_login_sso (Outcome from its column G)", false_login_sso is not None)
    if false_login_sso is not None:
        outcome_fill(false_login_sso, FALSE_LOGIN_SSO_COLS, "Clicked Link")
    snap("Step2_FalseLogin", base)

    # --- step 3: Mimecast - runs before GoPhish, so its value wins for anyone
    # it names. Employee Email against To (column C), taking Log Type (column
    # N). Only fills rows step 2 left empty.
    step("3", "Mimecast activity", mimecast is not None)
    if mimecast is not None:
        key, val = col_of(mimecast, ["To"], 2), col_of(mimecast, ["Log Type", "LogType"], 13)
        k, v = norm(mimecast[key]), canon_log_type(mimecast[val], log)
        # XLOOKUP semantics: a user with several Mimecast rows takes the FIRST
        # row in the file, not the strongest event
        ok = k.notna()
        hit = ident["Employee Email"].map(dict(zip(k[ok][::-1], v[ok][::-1])))
        fill = hit.notna() & hit.ne("") & base[COL_OUTCOME].eq("")
        base.loc[fill, COL_OUTCOME] = hit[fill]
        log(f"    Employee Email <- {key} -> {val}: {int(hit.notna().sum())} matched")
        log(f"    -> {int(fill.sum())} set, "
            f"{int((hit.notna() & ~fill).sum())} already resolved by an earlier check")
    snap("Step3_Mimecast", base)

    # --- step 4: GoPhish - the GoPhish column ONLY, never Outcome, and no
    # country filter. The events file is split into sheets first - the Linux
    # (non-Android) rows are moved out entirely, then one sheet per event - and
    # the GoPhish column is filled from those sheets, each pass only filling
    # rows the pass before it left unresolved. Outcome meets these values only
    # through step 6, which hands a leftover row its GoPhish value.
    # which file a row's GoPhish value came from ("non_de" / "de") - step 5
    # only takes a value into Outcome from the file matching the row's country
    gp_src = pd.Series("", index=base.index)

    def fill_gophish(frames, order, em, message, tag):
        """Each sheet in turn, filling only the rows still unresolved - the same
        filter-to-Not-Found-then-map shape the Outcome steps use. The value
        written is the sheet's own message, not a constant."""
        for event in order:
            frame = frames[event]
            k, v = norm(frame[em]), message[frame.index]
            ok = k.notna()
            # XLOOKUP semantics: the first row for a user wins
            hit = ident["Employee Email"].map(dict(zip(k[ok][::-1], v[ok][::-1])))
            fill = hit.notna() & base[COL_GOPHISH].eq("")
            base.loc[fill, COL_GOPHISH] = hit[fill]
            gp_src.loc[fill] = tag
            log(f"    '{event.lower()}' -> Employee Email <- {em}: {int(hit.notna().sum())} matched")
            log(f"    -> {int(fill.sum())} set, "
                f"{int((hit.notna() & ~fill).sum())} already resolved by an earlier sheet")

    step("4.1", "GoPhish activity (non-German)", gophish is not None)
    if gophish is not None:
        books[BOOK_GOPHISH], frames, em, message = gophish_split(
            gophish, GOPHISH_EVENTS, GOPHISH_DETAILS_IDX, log)
        fill_gophish(frames, GOPHISH_EVENTS, em, message, "non_de")

    # 4.2: the German file is split the same way but into four sheets, and fills
    # in a different order - Submitted Data first, then Clicked Link, then Email
    # Sent - over the rows 4.1 left unresolved.
    step("4.2", "GoPhish activity (German)", gophish_de is not None)
    if gophish_de is not None:
        books[BOOK_GOPHISH_DE], frames, em, message = gophish_split(
            gophish_de, GOPHISH_DE_EVENTS, GOPHISH_DE_DETAILS_IDX, log)
        fill_gophish(frames, GOPHISH_DE_FILL, em, message, "de")

    # Blank is the unresolved marker while 4.1 and 4.2 run. Whoever neither file
    # named reads Not Found - including anyone whose only events were Linux rows
    # that 4.1 or 4.2 excluded, or who sat on the wrong side of the country
    # filter. Step 6 turns an Outcome leftover with no GoPhish value into Email
    # Sent, so the report still settles every row.
    if gophish is not None or gophish_de is not None:
        rest = base[COL_GOPHISH].eq("")
        base.loc[rest, COL_GOPHISH] = NOT_FOUND
        log(f"    {int(rest.sum())} rows matched by neither file -> {NOT_FOUND}")

    # Blank means the outcome sources were never supplied; once any of them was,
    # a row nothing matched has been looked up and missed, same as the reporting
    # columns - say Not Found rather than leaving it ambiguous.
    if any(f is not None for f in (mimecast, false_login_sso, false_login, gophish, gophish_de)):
        base.loc[base[COL_OUTCOME].eq(""), COL_OUTCOME] = NOT_FOUND
    snap("Step4_GoPhish", base)

    # The tail: a leftover is a row whose Outcome still reads Not Found or User
    # Click. Order matters and each pass only touches what is still left:
    #   5. A GoPhish Submitted Data is definitive - it wins even over the
    #      reported lift (they submitted, then reported). Any country.
    #   5. A GoPhish Submitted Data is definitive - it wins even over the
    #      reported lift (they submitted, then reported). Any country.
    #   6. A reporter's click is doubted, whatever step wrote it: reported rows
    #      still leftover OR reading Clicked Link lift to Email Opened. Only a
    #      Submitted Data survives a report.
    #   7. Remaining leftovers take their GoPhish value, any country; whoever
    #      has none becomes Email Sent.
    unsettled = lambda: base[COL_OUTCOME].isin([NOT_FOUND, "User Click"])
    gp_val = lambda: ~base[COL_GOPHISH].isin(["", NOT_FOUND])

    log("  5   leftovers with GoPhish Submitted Data take it")
    take = unsettled() & base[COL_GOPHISH].eq("Submitted Data")
    base.loc[take, COL_OUTCOME] = base.loc[take, COL_GOPHISH]
    log(f"    {int(take.sum())} took Submitted Data")
    snap("Step5_Submitted", base)

    log("  6   reported leftovers and reported clickers -> Email Opened")
    yes = base[COL_REPORTED].eq("Yes")
    fix = (unsettled() | base[COL_OUTCOME].eq("Clicked Link")) & yes
    base.loc[fix, COL_OUTCOME] = "Email Opened"
    log(f"    Reported Yes: {int(yes.sum())}, lifted to Email Opened: {int(fix.sum())}")
    snap("Step6_Reported", base)

    log("  7   remaining leftovers take the GoPhish value, else Email Sent")
    take = unsettled() & gp_val()
    base.loc[take, COL_OUTCOME] = base.loc[take, COL_GOPHISH]
    sent = unsettled()
    base.loc[sent, COL_OUTCOME] = "Email Sent"
    log(f"    {int(take.sum())} took their GoPhish value, {int(sent.sum())} -> Email Sent")
    snap("Step7_Leftovers", base)

    # --- step 8: Phished Yes/No. Yes for the two outcomes that mean the user
    # acted on the phish, No for every other settled outcome. A row whose Outcome
    # is still blank had no outcome source at all, so it stays blank too.
    log("  8   Phished Yes/No")
    left = base[COL_OUTCOME].eq(NOT_FOUND)
    if left.any():   # step 6 should have settled all of these
        log(f"    ! {int(left.sum())} rows still read {NOT_FOUND} in Outcome - "
            "they count as No; check step 6")
    known = base[COL_OUTCOME].ne("")
    base.loc[known, COL_PHISHED] = (base.loc[known, COL_OUTCOME]
                                    .isin(PHISHED_YES).map({True: "Yes", False: "No"}))
    log(f"    {', '.join(sorted(PHISHED_YES))} -> Yes: {int(base[COL_PHISHED].eq('Yes').sum())}, "
        f"No: {int(base[COL_PHISHED].eq('No').sum())}")

    return base, books


# what each step reads, and the value column a hit copies - trace() compares
# these against where an identity actually sits in the file
TRACE_READS = {"false_login": FALSE_LOGIN_COLS, "false_login_sso": FALSE_LOGIN_SSO_COLS,
               "mimecast": ["To"], "o365": ["SenderAddress"], "soc": ["User"],
               "gophish": ["email"], "gophish_de": ["email"]}
TRACE_VALS = {"false_login": "Outcome", "false_login_sso": "Outcome",
              "mimecast": "Log Type", "o365": "Reported", "soc": "reported",
              "gophish": "message", "gophish_de": "message"}


def trace(email, srcs):
    """One user across every source file: their userbase identities, which
    columns of each file hold any of them, and whether that column is one the
    step reads. Explains a wrong match without the data leaving the machine."""
    e = norm(pd.Series([email])).iloc[0]
    if pd.isna(e):
        return [f"{email!r} does not look like an email"]
    out, idents = [f"tracing {e}"], {e}
    local = e.split("@")[0]

    def similar(df):
        """Values with the same local part but another domain/spelling - the
        usual reason a row the eye can see still misses the exact match."""
        hits = []
        for c in df.columns:
            v = norm(df[c])
            near = v[v.str.split("@").str[0].eq(local).fillna(False)].unique()
            hits += [f"      ~ {c}: {x}" for x in near[:3]]
        return hits[:6]

    base = srcs.get("base")
    if base is not None:
        ids = {c: norm(base[c]) for c in ID_COLS if c in base.columns}
        mask = pd.Series(False, index=base.index)
        for s in ids.values():
            mask |= s.eq(e)
        if not mask.any():
            out.append(f"! not in the userbase under any of: {', '.join(ids)}")
            out += similar(base[list(ids)])
        else:
            i = mask.idxmax()
            for c, s in ids.items():
                v = s.loc[i]
                out.append(f"  userbase {c}: {'(blank)' if pd.isna(v) else v}")
                if pd.notna(v):
                    idents.add(v)

    for name in TRACE_READS:
        df = srcs.get(name)
        if df is None:
            continue
        # false_login steps match every userbase identity; every other step
        # matches the Employee Email value only
        prim = idents if name.startswith("false_login") else {e}
        found = {}   # column -> rows holding one of this step's identities
        other = []   # columns holding one of the OTHER identities
        for c in df.columns:
            hit = norm(df[c]).isin(prim)
            if hit.any():
                found[str(c)] = df.index[hit]
            elif norm(df[c]).isin(idents).any():
                other.append(str(c))
        reads = TRACE_READS[name]
        used = [c for c in found if any(r.casefold() == c.strip().casefold() for r in reads)]
        if used:
            vcol = col_of(df, [TRACE_VALS[name]], 99) if name in TRACE_VALS else None
            vals = ""
            if vcol is not None:
                got = df.loc[[i for c in used for i in found[c]], vcol].dropna().unique()
                vals = f" -> {vcol}: {', '.join(map(repr, got[:6]))}"
            out.append(f"{name}: MATCHED via {', '.join(used)}{vals}")
        elif found:
            out.append(f"{name}: ! sits in {', '.join(found)} but the step reads "
                       f"{', '.join(reads)} - MISSED, header differs")
        elif other:
            out.append(f"{name}: ! found only in {', '.join(other)} under an SSO identity - "
                       "this step matches Employee Email only, so MISSED")
        else:
            near = similar(df)
            out.append(f"{name}: not in the file" + (" - but similar values exist:" if near else ""))
            out += near
    return out


def write_xlsx(path, sheets):
    with pd.ExcelWriter(path, engine="openpyxl") as w:
        for name, frame in sheets.items():
            frame.to_excel(w, sheet_name=name[:31], index=False)


def counts(df):
    if not len(df):
        return "  (empty)"
    line = lambda col: ", ".join(f"{k}={v}" for k, v in
                                 df[col].replace("", "(blank)").value_counts().items())
    return (f"  Outcome: {line(COL_OUTCOME)}\n  GoPhish: {line(COL_GOPHISH)}"
            f"\n  Phished: {line(COL_PHISHED)}")


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
             "de_keep", "de_mimeboth"]
    base = pd.DataFrame([base_row(n, "Germany" if n.startswith("de_") else "India") for n in names])

    # 2.1 matches on the Saviynt identity, 2.2 on the AD one - both must work.
    # de_keep already has an Outcome, so step 6 must leave it alone. The value
    # written is each row's own Outcome cell, not a constant per file.
    false_login = pd.DataFrame({"Email (SSO)": ["submitted@sso.x.com", "de_keep@sso.x.com"],
                                "Outcome": ["Submitted Data", "Submitted Data"]})
    false_login_sso = pd.DataFrame({"Email": ["Clicked <CLICKED@AD.X.COM>"],
                                    "Outcome": ["Clicked Link"]})
    # "submitted" is here too and must keep Submitted Data; "escalated" has
    # three rows - XLOOKUP takes the first (Email Sent), but their GoPhish
    # clicked link event already settled them in step 4 anyway
    # de_mimeboth has both a GoPhish event and a Mimecast row: step 4 runs
    # first, so the GoPhish value must win and Mimecast must not touch them
    mimecast = pd.DataFrame({
        "To": ["opened@x.com", "submitted@x.com", "clickreported@x.com", "de_click@x.com",
               "escalated@x.com", "escalated@x.com", "escalated@x.com", "de_mimeboth@x.com"],
        "Log Type": ["Email Opened", "Email Opened", "User Click", "User Click",
                     "Email Sent", "User Click", "Email Opened", "Email Opened"]})
    # value columns as in the real exports: O365 column K "Reported", SOC column
    # D "reported". The duplicate row pins XLOOKUP: the first row must win.
    o365 = pd.DataFrame({"SenderAddress": ["reported@x.com", "clickreported@x.com", "reported@x.com"],
                         "Reported": ["o365", "o365", "second-row-must-lose"]})
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
        "campaign_id": ["2"] * 7,
        "email": ["de_click@x.com", "de_sent@x.com", "de_sub@x.com",
                  "de_both@x.com", "de_both@x.com", "de_excluded@x.com", "de_mimeboth@x.com"],
        "time": ["09:00"] * 7,
        "message": ["Clicked Link", "Email Sent", "Submitted Data",
                    "Clicked Link", "Submitted Data", "Submitted Data", "Email Sent"],
        "Sort": [""] * 7,
        "details": ["Windows", "Linux Android", "Windows",
                    "Windows", "Windows", "Linux x86_64", "Windows"]})

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
                # the miss settles to Email Sent via the step 6 fallback
                assert list(final[COL_OUTCOME]) == [outcome, "Email Sent"], f"{where}: {list(final[COL_OUTCOME])}"

        # the same identity in a column the table does not list must not match
        base = pd.DataFrame({"Employee Email": ["hit@x.com"]})
        src = pd.DataFrame({"Some Other Column": ["hit@x.com"], **{c: ["other@x.com"] for c in cols}})
        final, _ = run(base, log=lambda *_: None, **{kw: src})
        assert list(final[COL_OUTCOME]) == ["Email Sent"], f"{kw} matched an unlisted column"

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


def check_outcome_copy():
    """Step 2 copies each row's own Outcome cell: the first matching row wins
    (XLOOKUP), a blank cell leaves the row open for a later pair, and the pair
    order is S->D, S->E, then the SSO identities."""
    base = pd.DataFrame({"Employee Email": ["a@x.com", "b@x.com", "c@x.com"],
                         "SSOUPN as per Saviynt": ["a@sso.x.com", "b@sso.x.com", "c@sso.x.com"],
                         "SSOUPN as per AD (O365)": ["a@ad.x.com", "b@ad.x.com", "c@ad.x.com"]})
    fl = pd.DataFrame({
        "Username":    ["a@x.com", "a@x.com", "c@x.com", "c@sso.x.com", "x"],
        "Email (SSO)": ["x",       "x",       "x",       "x",           "b@sso.x.com"],
        "Outcome":     ["Weird Value", "Second Row", "", "Late", "From E"]})
    final, _ = run(base, false_login=fl, log=lambda *_: None)
    # a: first row wins, not the second; b: found via Saviynt x Email (SSO);
    # c: its S->D hit had a blank Outcome, so the AD->D pair filled it
    assert list(final[COL_OUTCOME]) == ["Weird Value", "From E", "Late"], list(final[COL_OUTCOME])


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
    # no space at all. The fourth did not report it, so step 6 settles it to
    # Email Sent (no GoPhish value to take).
    assert list(final[COL_OUTCOME]) == ["Email Opened"] * 3 + ["Email Sent"], list(final[COL_OUTCOME])

    # a GoPhish Submitted Data beats the reported lift; a GoPhish Clicked Link
    # does not - a reporter's click is doubted, their submit is not
    base = pd.DataFrame({"Employee Email": ["a@x.com", "b@x.com"],
                         "Country": ["Germany", "Germany"]})
    de_gp = pd.DataFrame({"campaign_id": ["1", "1"], "email": ["a@x.com", "b@x.com"],
                          "time": ["09:00"] * 2, "message": ["Submitted Data", "Clicked Link"],
                          "Sort": ["", ""], "details": ["Windows"] * 2})
    o365 = pd.DataFrame({"SenderAddress": ["a@x.com", "b@x.com"], "Reported": ["o365", "o365"]})
    none_of_them = pd.DataFrame({"To": ["nobody@x.com"], "Log Type": ["Email Sent"]})
    final, _ = run(base, gophish_de=de_gp, o365=o365, mimecast=none_of_them, log=lambda *_: None)
    assert list(final[COL_OUTCOME]) == ["Submitted Data", "Email Opened"], list(final[COL_OUTCOME])

    # an unreported leftover takes its GoPhish value whatever the country
    base = pd.DataFrame({"Employee Email": ["c@x.com"], "Country": ["India"]})
    mm2 = pd.DataFrame({"To": ["c@x.com"], "Log Type": ["User Click"]})
    gp2 = pd.DataFrame({"campaign_id": ["1"], "email": ["c@x.com"], "time": ["09:00"],
                        "message": ["Clicked Link"], "details": ["Windows"]})
    final, _ = run(base, gophish=gp2, mimecast=mm2, log=lambda *_: None)
    assert list(final[COL_OUTCOME]) == ["Clicked Link"], list(final[COL_OUTCOME])

    # a reported clicker lifts to Email Opened even when step 2 wrote the click
    sso2 = pd.DataFrame({"Email": ["c@x.com"], "Outcome": ["Clicked Link"]})
    soc2 = pd.DataFrame({"User": ["c@x.com"], "reported": ["soc-support"]})
    final, _ = run(base, false_login_sso=sso2, soc=soc2, log=lambda *_: None)
    assert list(final[COL_OUTCOME]) == ["Email Opened"], list(final[COL_OUTCOME])


def check_mimecast_columns():
    """Step 3 finds To and Log Type by position (C and N) when the headers differ."""
    base = pd.DataFrame({"Employee Email": ["a@x.com"]})
    wide = {chr(65 + i): [""] for i in range(15)}       # 15 columns, A..O
    wide["C"], wide["N"] = ["A@X.COM"], ["Email Opened"]  # position 2 and 13
    final, _ = run(base, mimecast=pd.DataFrame(wide), log=lambda *_: None)
    assert list(final[COL_OUTCOME]) == ["Email Opened"], list(final[COL_OUTCOME])

    # XLOOKUP semantics: the first row for a user wins, not the strongest event
    mm = pd.DataFrame({"To": ["a@x.com", "a@x.com"], "Log Type": ["Email Opened", "User Click"]})
    final, _ = run(base, mimecast=mm, log=lambda *_: None)
    assert list(final[COL_OUTCOME]) == ["Email Opened"], list(final[COL_OUTCOME])


def selftest():
    check_read_any()
    check_outcome_pairs()
    check_outcome_copy()
    check_lookup_fallback()
    check_mimecast_columns()
    check_step5_spelling()
    check_gophish_file_order()
    snaps = []
    final, books = run(log=lambda *_: None, snap=lambda n, d: snaps.append(n), **fixtures())
    assert snaps == ["Step1_Reporting", "Step2_FalseLogin", "Step3_Mimecast", "Step4_GoPhish",
                     "Step5_Submitted", "Step6_Reported", "Step7_Leftovers"], snaps
    f = final.set_index("Employee Name")

    want = {"submitted": "Submitted Data",  # 2.1 keeps it; step 4 may not overwrite
            "clicked": "Clicked Link",      # 2.2, matched via the AD identity
            # Mimecast runs before GoPhish, so its first row wins for anyone it
            # names; GoPhish acted events fill only what Mimecast left empty
            "opened": "Email Opened",       # Mimecast row; GoPhish only had Email Sent
            "escalated": "Email Sent",      # Mimecast first row is Email Sent - it wins
            "clickreported": "Email Opened",  # only in Mimecast; step 5 lifted the click
            "reported": "Email Opened",     # Not Found + reported -> the step 6 lift
            "untouched": "Email Sent",      # was Not Found, no report -> step 6 fallback
            "de_sub": "Submitted Data",
            "de_click": "Clicked Link",
            "de_sent": "Email Sent",
            "de_both": "Submitted Data",
            "de_excluded": "Email Sent",    # GoPhish fell back to Email Sent
            "de_keep": "Submitted Data",    # already had an Outcome from step 2
            "de_mimeboth": "Email Opened"}  # GoPhish Email Sent left it open; Mimecast filled
    for name, outcome in want.items():
        assert f.loc[name, COL_OUTCOME] == outcome, f"{name}: {f.loc[name, COL_OUTCOME]!r} != {outcome!r}"

    # step 8: Yes only for the two outcomes that mean the user acted
    for name, outcome in f[COL_OUTCOME].items():
        want_p = "Yes" if outcome in PHISHED_YES else "No"
        assert f.loc[name, COL_PHISHED] == want_p, f"{name}: {outcome!r} -> {f.loc[name, COL_PHISHED]!r}"
    assert set(f[COL_PHISHED]) == {"Yes", "No"}, set(f[COL_PHISHED])
    # with no outcome source at all, Outcome is blank and Phished stays blank
    blank, _ = run(pd.DataFrame({"Employee Email": ["a@x.com"]}), log=lambda *_: None)
    assert list(blank[COL_PHISHED]) == [""], list(blank[COL_PHISHED])
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
    assert list(de["email sent"]["email"]) == ["de_sent@x.com", "de_mimeboth@x.com"]
    assert list(de["submitted data"]["email"]) == ["de_sub@x.com", "de_both@x.com"]

    sheets = books[BOOK_GOPHISH]
    assert list(sheets[SHEET_EXCLUDED]["email"]) == ["untouched@x.com"], sheets[SHEET_EXCLUDED]
    assert list(sheets["clicked link"]["email"]) == ["clicked@x.com", "escalated@x.com"]
    assert list(sheets["email sent"]["email"]) == ["clicked@x.com", "opened@x.com"]
    # whoever neither file named falls through to Email Sent, never Not Found
    want_gp = {"clicked": "Clicked Link",     # in both sheets, Clicked Link runs first
               "escalated": "Clicked Link",
               "opened": "Email Sent",
               "untouched": NOT_FOUND,        # its only row was excluded as Linux
               "submitted": NOT_FOUND, "reported": NOT_FOUND,
               "de_sub": "Submitted Data",    # German, filled by 4.2
               "de_click": "Clicked Link",
               "de_sent": "Email Sent",
               "de_both": "Submitted Data",   # in two German sheets, this one fills first
               "de_excluded": NOT_FOUND,      # its rows were excluded as Linux
               "de_keep": NOT_FOUND,          # neither file names them
               "de_mimeboth": "Email Sent"}
    # steps 6 and 7 between them settle every row, so Outcome has no leftovers
    assert NOT_FOUND not in set(f[COL_OUTCOME]), set(f[COL_OUTCOME])
    assert "User Click" not in set(f[COL_OUTCOME]), set(f[COL_OUTCOME])
    for name, value in want_gp.items():
        assert f.loc[name, COL_GOPHISH] == value, f"{name}: {f.loc[name, COL_GOPHISH]!r} != {value!r}"

    # trace: a false_login step matches any identity, the rest Employee Email only
    t = trace("clicked@x.com", fixtures())
    assert any(s.startswith("false_login_sso: MATCHED via Email") for s in t), t
    assert any(s == "mimecast: not in the file" for s in t), t
    assert any(s.startswith("gophish: MATCHED via email") and "Clicked Link" in s for s in t), t
    t = trace("submitted@x.com", dict(
        base=fixtures()["base"],
        mimecast=pd.DataFrame({"To": ["submitted@sso.x.com"], "Log Type": ["User Click"]})))
    assert any(s.startswith("mimecast:") and "MISSED" in s for s in t), t
    # an email in the file under another domain shows up as a similar value
    t = trace("someone@x.com", dict(gophish_de=pd.DataFrame(
        {"email": ["someone@de.x.com"], "message": ["Clicked Link"]})))
    assert any("similar values exist" in s for s in t), t
    assert any("someone@de.x.com" in s for s in t), t

    print("selftest: all checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
