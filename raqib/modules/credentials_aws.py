"""Read an IAM credential report to add findings the authorization details cannot
show: access keys that are old and still active, console users without a second
factor, and a root account that still carries access keys. These are the
credentials an attacker harvests first, so an audit should surface them.

The credential report is the CSV that `aws iam generate-credential-report` and
`aws iam get-credential-report` produce. This is optional. Raqib works from the
authorization details alone and reads a credential report only when one is given.
"""

import csv
import datetime
import io


def _parse_date(value):
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    try:
        v = value.replace("+00:00", "Z")
        return datetime.datetime.strptime(v[:19], "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


def _age_days(value, now):
    d = _parse_date(value)
    if d is None:
        return None
    return (now - d).days


def _finding(fid, severity, title, user, detail, fix, tactic):
    return {
        "id": fid,
        "severity": severity,
        "title": title,
        "principal": {"kind": "user", "name": user, "arn": ""} if user else None,
        "detail": detail,
        "fix": fix,
        "tactic": tactic,
        "refs": [],
    }


def check(csv_text, max_key_age_days=90, now=None):
    now = now or datetime.datetime.utcnow()
    findings = []
    n = 0
    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        user = row.get("user", "")
        is_root = user == "<root_account>"

        for slot in ("access_key_1", "access_key_2"):
            active = row.get(slot + "_active") == "true"
            if not active:
                continue
            age = _age_days(row.get(slot + "_last_rotated"), now)
            if is_root:
                findings.append(_finding("c" + str(n), "critical", "Root account has an active access key",
                    None, "The root account still has an active access key. Root keys cannot be scoped and are a first target once an account is breached.",
                    "Delete the root access keys and operate through least privilege roles instead.", "exposure"))
                n += 1
                continue
            if age is not None and age > max_key_age_days:
                findings.append(_finding("c" + str(n), "medium", "Access key is old and still active",
                    user, f"An access key for {user} was last rotated {age} days ago and is still active. A leaked long lived key stays valid until it is rotated.",
                    f"Rotate keys on a schedule shorter than {max_key_age_days} days, and remove keys that are not in use.", "exposure"))
                n += 1

        password_enabled = row.get("password_enabled") == "true"
        mfa_active = row.get("mfa_active") == "true"
        if is_root and not mfa_active:
            findings.append(_finding("c" + str(n), "critical", "Root account has no multi factor authentication",
                None, "The root account can sign in to the console with no second factor.",
                "Enable a hardware or virtual multi factor device on the root account.", "exposure"))
            n += 1
        elif password_enabled and not mfa_active:
            findings.append(_finding("c" + str(n), "high", "Console user without multi factor authentication",
                user, f"{user} can sign in to the console with a password and no second factor, so a phished or reused password is enough to sign in.",
                "Require multi factor authentication for every console user.", "exposure"))
            n += 1

        if not is_root and row.get("access_key_1_active") == "true" and row.get("access_key_2_active") == "true":
            findings.append(_finding("c" + str(n), "medium", "User has two active access keys",
                user, f"{user} has two active access keys. A second key is a common way an intruder keeps a foothold, and it widens the surface a leak can come from.",
                "Keep one active key per user, and remove the second unless a rotation is in progress.", "persistence"))
            n += 1

    return findings
