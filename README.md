# Phishing Report Preparation

Turns the eight phishing-campaign exports into the Final Report, following the SOP in
[`steps.txt`](steps.txt) — Part 1 (non-German) over the whole userbase, then Part 2
(German) over the `Country = Germany` subset of that result.

Six columns are derived: `Outcome`, `GoPhish`, `Reported to O365`, `Reported to SOC`,
`Reported (Yes/No)`, `Phished Yes/No`.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Only pandas and openpyxl. Python 3.10+.

## Use

Command line:

```powershell
.\.venv\Scripts\python.exe phishing_report.py --base UserBase_V2.xlsx `
    --false-login "False_login_data-Q2-Submitted.xlsx" `
    --false-login-sso "false_login_sso_data-Q2-Clicked Link.xlsx" `
    --mimecast mimecast_combine.xlsx `
    --gophish GoPhish_Events_non_german.xlsx `
    --o365 "User Reported-Microsoft 365Report button.xlsx" `
    --soc "User Reported SOC-Support.xlsx" `
    --gophish-de Events_GermanOnly.xlsx `
    --out output
```

Browser:

```powershell
.\.venv\Scripts\python.exe serve.py          # -> http://127.0.0.1:8020
```

Drop the files in, hit **Run pipeline**, read the counts, download the reports. Each run
lands in `runs/run_<timestamp>/` with its inputs beside its outputs.

Only `--base` is required. Leave any other source out and its step is skipped and says so.
`.csv` is accepted anywhere `.xlsx` is.

## Output

| File | What |
|---|---|
| `Final_Report.xlsx` | the userbase plus the six columns (Part 1) |
| `German_Report.xlsx` | the Germany subset after Part 2 reconciliation |
| `GoPhish_Tabs.xlsx` | the split event tabs — steps 3.2 and German 2 |

Per the SOP these are two separate deliverables; German values are not merged back into
`Final_Report.xlsx`.

## Checking it

```powershell
.\.venv\Scripts\python.exe phishing_report.py --selftest
```

Ten synthetic users, one per rule, each named for the outcome it must end on: step 2.1
beating a weaker Mimecast row, 2.2 matching on the AD identity, step 5 rule 1, rule 2
overriding rule 1, the Linux/Android filter, and the three German cases.

`--write-samples sample_data` dumps those same fixtures as `.xlsx` so the UI has
something to run against.

## Judgement calls

`steps.txt` leaves four things open. Each is one line in the code:

1. **Step 2 precedence.** 2.1, 2.2 and 2.3 all write `Outcome`. Applied weakest-first
   (Mimecast → Clicked Link → Submitted Data), so a submitter who also has a Mimecast
   `Email Opened` ends on `Submitted Data`.
2. **Mimecast duplicates.** A user with several `Log Type` rows keeps the strongest:
   `User Click` > `Email Opened` > `Email Sent`.
3. **Step 5 rule order.** Rule 2 runs after rule 1, so a confirmed GoPhish click beats the
   "they reported it" downgrade — a user caught by both ends `Clicked Link`, `Phished = Yes`.
4. **`Outcome = User Click`** is absent from the step 6 table, so it falls through to
   `Phished = No`.

Column header is `Phished Yes/No`, per `files & column.txt`; `steps.txt` writes it
`Phished (Yes/No)`. Change `COL_PHISHED` if the workbook needs the other spelling.

## Input handling

Source exports drift. Emails are normalised (`Name <a@b.com>`, `mailto:`, quotes, case)
before matching, and a header hidden under banner rows is found by scanning the first 15
rows. Steps 2.1 and 2.2 match on all three identity columns (`Employee Email`,
`SSOUPN as per Saviynt`, `SSOUPN as per AD (O365)`); everything else matches on
`Employee Email`, per the SOP.

## Layout

```
phishing_report.py   the pipeline, the CLI, the selftest
serve.py             stdlib http.server backend for the test UI
web/                 index.html · app.js · styles.css
steps.txt            the SOP
files & column.txt   source-export column layouts
```

`runs/`, `output/` and `sample_data/` are gitignored — runs hold real uploaded exports.
