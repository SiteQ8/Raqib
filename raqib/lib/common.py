"""Helpers shared by the tactic checks: building a finding, labelling a principal,
reading an account id out of an arn, and coercing a value to a list."""

def _finding(fid, severity, title, principal, detail, fix, tactic, refs=None):
    return {
        "id": fid,
        "severity": severity,
        "title": title,
        "principal": {"kind": principal.kind, "name": principal.name, "arn": principal.arn} if principal else None,
        "detail": detail,
        "fix": fix,
        "tactic": tactic,
        "refs": refs or [],
    }


def _principal_label(p):
    return (p.kind + " " + p.name) if p else "the account"


def _account_id(arn):
    parts = str(arn).split(":")
    return parts[4] if len(parts) > 4 and parts[4].isdigit() else None


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def summarize(findings, account):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    principals_with = len({f["principal"]["arn"] for f in findings if f.get("principal")})
    principals = len(getattr(account, "principals", []) or [])
    return {
        "counts": counts,
        "total": len(findings),
        "principals": principals,
        "principals_with_findings": principals_with,
    }
