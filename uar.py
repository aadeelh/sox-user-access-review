"""
Automated User Access Review (UAR) tool for SOX ITGC testing.

Compares an HR roster with an application user listing and runs five tests:
  T1  Terminated employees who still have active access
  T2  Orphan accounts with no matching employee in the HR roster
  T3  Segregation of duties (SoD) conflicts
  T4  Dormant accounts with no login in the last N days
  T5  Privileged access listing for manager review

Results are written to an Excel exception report that can be attached to the
audit work paper. The report also records population counts and SHA-256 hashes
of each input file, so the reviewer can show the data used was complete and
unchanged (completeness and accuracy of the report used as evidence).

Usage:
    python uar.py --hr sample_data/hr_roster.csv \
                  --users sample_data/app_users.csv \
                  --sod sample_data/sod_rules.csv \
                  --as-of 2026-10-31 \
                  --out UAR_Exception_Report.xlsx
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import date, datetime
from pathlib import Path

import pandas as pd

DEFAULT_PRIVILEGED_ROLES = ["SYS_ADMIN", "DB_ADMIN", "CHANGE_DEPLOYER"]
DEFAULT_DORMANT_DAYS = 90

REQUIRED_COLUMNS = {
    "hr": ["employee_id", "full_name", "department", "employment_status", "termination_date"],
    "users": ["user_id", "employee_id", "account_status", "account_type", "roles", "last_login"],
    "sod": ["rule_id", "role_a", "role_b", "risk"],
}

EXCEPTION_COLUMNS = ["test_id", "test_name", "severity", "user_id", "employee_id",
                     "full_name", "department", "detail", "recommended_action"]


# --------------------------------------------------------------------------- #
# Loading and validation
# --------------------------------------------------------------------------- #
def sha256_of(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_csv(path: str | Path, kind: str) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str).fillna("")
    df.columns = [c.strip().lower() for c in df.columns]
    missing = [c for c in REQUIRED_COLUMNS[kind] if c not in df.columns]
    if missing:
        raise ValueError(f"{path}: missing required column(s): {', '.join(missing)}")
    for col in df.columns:
        df[col] = df[col].str.strip()
    return df


def prepare(hr: pd.DataFrame, users: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    hr = hr.copy()
    users = users.copy()
    hr["termination_date"] = pd.to_datetime(hr["termination_date"], errors="coerce")
    users["last_login"] = pd.to_datetime(users["last_login"], errors="coerce")
    users["role_list"] = users["roles"].apply(
        lambda s: sorted({r.strip().upper() for r in s.split(";") if r.strip()}))
    return hr, users


def active_accounts(users: pd.DataFrame) -> pd.DataFrame:
    return users[users["account_status"].str.lower() == "active"]


def with_hr(users: pd.DataFrame, hr: pd.DataFrame) -> pd.DataFrame:
    cols = ["employee_id", "full_name", "department", "employment_status", "termination_date"]
    return users.merge(hr[cols], on="employee_id", how="left")


def make_exceptions(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=EXCEPTION_COLUMNS)


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_terminated_with_access(hr, users, as_of) -> pd.DataFrame:
    """T1: terminated employees whose application account is still active."""
    df = with_hr(active_accounts(users), hr)
    df = df[(df["employment_status"].str.lower() == "terminated")
            & (df["termination_date"] <= pd.Timestamp(as_of))]
    rows = []
    for _, r in df.iterrows():
        used_after = pd.notna(r["last_login"]) and r["last_login"] > r["termination_date"]
        days_open = (pd.Timestamp(as_of) - r["termination_date"]).days
        detail = (f"Terminated {r['termination_date']:%Y-%m-%d}; account still active "
                  f"{days_open} days later")
        if used_after:
            detail += f"; account used after termination (last login {r['last_login']:%Y-%m-%d})"
        rows.append({
            "test_id": "T1", "test_name": "Terminated user with active access",
            "severity": "Critical" if used_after else "High",
            "user_id": r["user_id"], "employee_id": r["employee_id"],
            "full_name": r["full_name"], "department": r["department"], "detail": detail,
            "recommended_action": ("Disable immediately and review activity after termination"
                                   if used_after else "Disable account and confirm with HR"),
        })
    return make_exceptions(rows)


def test_orphan_accounts(hr, users, as_of) -> pd.DataFrame:
    """T2: active user accounts that cannot be traced to an employee."""
    df = active_accounts(users)
    df = df[df["account_type"].str.lower() != "service"]
    df = df[~df["employee_id"].isin(hr["employee_id"])]
    rows = [{
        "test_id": "T2", "test_name": "Orphan account (no HR match)", "severity": "High",
        "user_id": r["user_id"], "employee_id": r["employee_id"], "full_name": "",
        "department": "",
        "detail": ("No employee ID on account" if not r["employee_id"]
                   else f"Employee ID {r['employee_id']} not found in HR roster"),
        "recommended_action": "Identify owner; disable if no business justification",
    } for _, r in df.iterrows()]
    return make_exceptions(rows)


def test_sod_conflicts(hr, users, sod, as_of) -> pd.DataFrame:
    """T3: users holding both roles of a conflicting pair."""
    df = with_hr(active_accounts(users), hr)
    rows = []
    for _, r in df.iterrows():
        roles = set(r["role_list"])
        for _, rule in sod.iterrows():
            a, b = rule["role_a"].upper(), rule["role_b"].upper()
            if a in roles and b in roles:
                rows.append({
                    "test_id": "T3", "test_name": "Segregation of duties conflict",
                    "severity": "High", "user_id": r["user_id"],
                    "employee_id": r["employee_id"], "full_name": r.get("full_name", "") or "",
                    "department": r.get("department", "") or "",
                    "detail": f"{rule['rule_id']}: holds {a} and {b}. {rule['risk']}",
                    "recommended_action": "Remove one role or document a mitigating control",
                })
    return make_exceptions(rows)


def test_dormant_accounts(hr, users, as_of, dormant_days=DEFAULT_DORMANT_DAYS) -> pd.DataFrame:
    """T4: active accounts with no login in the last `dormant_days` days."""
    df = with_hr(active_accounts(users), hr)
    cutoff = pd.Timestamp(as_of) - pd.Timedelta(days=dormant_days)
    df = df[df["last_login"].isna() | (df["last_login"] < cutoff)]
    rows = []
    for _, r in df.iterrows():
        last = "never" if pd.isna(r["last_login"]) else f"{r['last_login']:%Y-%m-%d}"
        rows.append({
            "test_id": "T4", "test_name": f"Dormant account (> {dormant_days} days)",
            "severity": "Medium", "user_id": r["user_id"], "employee_id": r["employee_id"],
            "full_name": r.get("full_name", "") or "", "department": r.get("department", "") or "",
            "detail": f"Last login {last}",
            "recommended_action": "Confirm continued need with manager or disable",
        })
    return make_exceptions(rows)


def test_privileged_access(hr, users, as_of, privileged_roles=None) -> pd.DataFrame:
    """T5: list of users with privileged roles, for manager sign-off."""
    priv = {r.upper() for r in (privileged_roles or DEFAULT_PRIVILEGED_ROLES)}
    df = with_hr(active_accounts(users), hr)
    rows = []
    for _, r in df.iterrows():
        held = sorted(set(r["role_list"]) & priv)
        if held:
            rows.append({
                "test_id": "T5", "test_name": "Privileged access for review",
                "severity": "Review", "user_id": r["user_id"], "employee_id": r["employee_id"],
                "full_name": r.get("full_name", "") or "", "department": r.get("department", "") or "",
                "detail": f"Privileged role(s): {', '.join(held)}",
                "recommended_action": "Manager to confirm access is appropriate for job role",
            })
    return make_exceptions(rows)


def run_all(hr, users, sod, as_of, dormant_days=DEFAULT_DORMANT_DAYS, privileged_roles=None):
    hr, users = prepare(hr, users)
    results = {
        "T1": test_terminated_with_access(hr, users, as_of),
        "T2": test_orphan_accounts(hr, users, as_of),
        "T3": test_sod_conflicts(hr, users, sod, as_of),
        "T4": test_dormant_accounts(hr, users, as_of, dormant_days),
        "T5": test_privileged_access(hr, users, as_of, privileged_roles),
    }
    data_issues = []
    dup = users[users["user_id"].duplicated(keep=False)]["user_id"].unique()
    if len(dup):
        data_issues.append(f"Duplicate user IDs in user listing: {', '.join(dup)}")
    bad_dates = users[users["last_login"].isna()]["user_id"].tolist()
    if bad_dates:
        data_issues.append(f"Missing or invalid last_login for: {', '.join(bad_dates)}")
    return results, data_issues


# --------------------------------------------------------------------------- #
# Excel report
# --------------------------------------------------------------------------- #
def write_report(out_path, results, data_issues, meta) -> None:
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    all_exc = pd.concat(results.values(), ignore_index=True)
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Review": 3}
    all_exc = all_exc.sort_values(by=["severity", "test_id", "user_id"],
                                  key=lambda s: s.map(sev_order) if s.name == "severity" else s)

    summary_rows = [
        ("Control", "User access review (ITGC: Access to Programs and Data)"),
        ("Review as-of date", meta["as_of"]),
        ("Report generated", meta["generated"]),
        ("Prepared by", meta["preparer"]),
        ("", ""),
        ("Population: HR roster records", meta["hr_count"]),
        ("Population: application accounts", meta["user_count"]),
        ("Population: active accounts tested", meta["active_count"]),
        ("SoD rules applied", meta["sod_count"]),
        ("", ""),
        ("SHA-256 HR roster", meta["hr_hash"]),
        ("SHA-256 user listing", meta["users_hash"]),
        ("SHA-256 SoD rules", meta["sod_hash"]),
        ("", ""),
    ]
    for tid, df in results.items():
        name = df["test_name"].iloc[0] if len(df) else TEST_NAMES[tid]
        summary_rows.append((f"{tid} {name}", len(df)))
    summary_rows.append(("Total exceptions", len(all_exc)))
    summary_rows.append(("", ""))
    summary_rows.append(("Data quality notes", "None" if not data_issues else ""))
    for issue in data_issues:
        summary_rows.append(("", issue))

    with pd.ExcelWriter(out_path, engine="openpyxl") as xw:
        pd.DataFrame(summary_rows, columns=["Item", "Value"]).to_excel(xw, sheet_name="Summary", index=False)
        all_exc.to_excel(xw, sheet_name="All Exceptions", index=False)
        for tid, df in results.items():
            df.to_excel(xw, sheet_name=f"{tid} Detail", index=False)

        fills = {"Critical": "F4B6B6", "High": "F9D9C5", "Medium": "FCEFC7", "Review": "DCE9F7"}
        for ws in xw.book.worksheets:
            ws.freeze_panes = "A2"
            for cell in ws[1]:
                cell.font = Font(bold=True, color="FFFFFF")
                cell.fill = PatternFill("solid", fgColor="44546A")
            for col in ws.columns:
                width = max(len(str(c.value or "")) for c in col)
                ws.column_dimensions[get_column_letter(col[0].column)].width = min(max(width + 2, 10), 70)
            if ws.title != "Summary":
                sev_col = EXCEPTION_COLUMNS.index("severity") + 1
                for row in ws.iter_rows(min_row=2):
                    sev = row[sev_col - 1].value
                    if sev in fills:
                        row[sev_col - 1].fill = PatternFill("solid", fgColor=fills[sev])
                    for c in row:
                        c.alignment = Alignment(vertical="top", wrap_text=True)


TEST_NAMES = {
    "T1": "Terminated user with active access",
    "T2": "Orphan account (no HR match)",
    "T3": "Segregation of duties conflict",
    "T4": "Dormant account",
    "T5": "Privileged access for review",
}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Automated user access review for SOX ITGC testing")
    p.add_argument("--hr", required=True, help="HR roster CSV")
    p.add_argument("--users", required=True, help="Application user listing CSV")
    p.add_argument("--sod", required=True, help="SoD conflict rules CSV")
    p.add_argument("--as-of", default=date.today().isoformat(), help="Review date, YYYY-MM-DD")
    p.add_argument("--dormant-days", type=int, default=DEFAULT_DORMANT_DAYS)
    p.add_argument("--privileged-roles", default=",".join(DEFAULT_PRIVILEGED_ROLES),
                   help="Comma-separated list of privileged roles")
    p.add_argument("--preparer", default="", help="Name of the person running the review")
    p.add_argument("--out", default="UAR_Exception_Report.xlsx")
    a = p.parse_args(argv)

    as_of = datetime.strptime(a.as_of, "%Y-%m-%d").date()
    hr = load_csv(a.hr, "hr")
    users = load_csv(a.users, "users")
    sod = load_csv(a.sod, "sod")
    priv = [r.strip() for r in a.privileged_roles.split(",") if r.strip()]

    results, data_issues = run_all(hr, users, sod, as_of, a.dormant_days, priv)
    meta = {
        "as_of": as_of.isoformat(),
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "preparer": a.preparer,
        "hr_count": len(hr), "user_count": len(users),
        "active_count": int((users["account_status"].str.lower() == "active").sum()),
        "sod_count": len(sod),
        "hr_hash": sha256_of(a.hr), "users_hash": sha256_of(a.users), "sod_hash": sha256_of(a.sod),
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    write_report(a.out, results, data_issues, meta)

    print(f"User access review as of {as_of}")
    print(f"  HR records: {meta['hr_count']}   Accounts: {meta['user_count']}   "
          f"Active: {meta['active_count']}")
    for tid, df in results.items():
        print(f"  {tid} {TEST_NAMES[tid]:<38} {len(df):>3} exception(s)")
    for issue in data_issues:
        print(f"  Data note: {issue}")
    print(f"Report written to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
