# Automated User Access Review (SOX ITGC)

A Python tool that automates the quarterly user access review, one of the key IT general controls (ITGC) tested in SOX audits under Access to Programs and Data.

It compares an HR roster with an application user listing, runs five standard access tests, and writes an Excel exception report that can be attached to an audit work paper.

## Why this matters

In many companies the user access review is still done by hand: someone exports two lists and compares them in Excel with lookups. That is slow, and it is easy to miss a terminated user or a conflicting role pair. This tool runs the same checks in seconds, the same way every time, and records the evidence an auditor needs.

## Tests performed

| Test | What it finds | Severity |
|------|---------------|----------|
| T1 | Terminated employees whose account is still active. Flagged Critical if the account was used after the termination date | Critical / High |
| T2 | Orphan accounts that cannot be traced to any employee (service accounts excluded) | High |
| T3 | Segregation of duties (SoD) conflicts, based on a rules file of conflicting role pairs | High |
| T4 | Dormant accounts with no login in the last 90 days (configurable) | Medium |
| T5 | Users with privileged roles (for example SYS_ADMIN, DB_ADMIN), listed for manager sign-off | Review |

## Audit evidence features

- **Population counts:** HR records, total accounts and active accounts tested are recorded on the Summary sheet.
- **File integrity:** a SHA-256 hash of each input file is recorded. This supports the completeness and accuracy of the data used (IPE), because anyone can re-hash the source files and confirm they were not changed.
- **Data quality checks:** duplicate user IDs and missing login dates are reported.
- **Input validation:** the tool stops with a clear message if a required column is missing.

## How to run

```bash
pip install -r requirements.txt

python uar.py --hr sample_data/hr_roster.csv \
              --users sample_data/app_users.csv \
              --sod sample_data/sod_rules.csv \
              --as-of 2026-10-31 \
              --preparer "Your Name" \
              --out sample_output/UAR_Exception_Report.xlsx
```

Optional settings:

- `--dormant-days 60` changes the dormant account threshold (default 90)
- `--privileged-roles SYS_ADMIN,DB_ADMIN` sets which roles count as privileged

Run the tests:

```bash
python -m pytest -q
```

## Input files

**hr_roster.csv:** employee_id, full_name, department, employment_status (Active / Terminated), termination_date, manager

**app_users.csv:** user_id, employee_id, account_status (Active / Disabled), account_type (User / Service), roles (separated by `;`), last_login

**sod_rules.csv:** rule_id, role_a, role_b, risk

## Output

An Excel workbook with:

- **Summary:** control name, review date, preparer, population counts, file hashes, exception counts per test
- **All Exceptions:** every exception sorted by severity, with a recommended action
- **T1 to T5 Detail:** one sheet per test

## Sample results

Running on the included sample data (20 employees, 20 accounts) finds 17 exceptions, including two terminated users who logged in after leaving, two orphan accounts and five SoD conflicts.

## Sample data

All names and records in `sample_data` are made up for demonstration.

## Project structure

```
uar-tool/
  uar.py                 main script
  requirements.txt
  sample_data/           example HR roster, user listing and SoD rules
  sample_output/         example Excel report
  tests/test_uar.py      automated tests (pytest)
```
