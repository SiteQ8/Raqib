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
