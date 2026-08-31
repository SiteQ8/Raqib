"""Lateral movement checks: the defensive mirror of S7aba's lateral modules.

Reads role trust policies for the ones that let the wrong caller in, roles assumable
by anyone, roles that trust an external account, and federated trust with no condition.
"""

from raqib.lib.common import _finding, _principal_label, _account_id, _as_list

def check_trust(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if p.kind != "role" or not p.trust:
            continue
        for stmt in _as_list(p.trust.get("Statement")):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            has_condition = bool(stmt.get("Condition"))
            aws = principal.get("AWS") if isinstance(principal, dict) else None
            aws_list = aws if isinstance(aws, list) else ([aws] if aws else [])
            if principal == "*" or "*" in aws_list:
                findings.append(_finding(
                    "t" + str(n), "critical", "Role can be assumed by anyone",
                    p, f"The trust policy of role {p.name} allows any principal to assume it" + (", though a condition is present, so verify the condition truly restricts who can assume it." if has_condition else ", with no condition to restrict it. Any AWS account can take on this role."),
                    "Restrict the trust policy to the specific accounts, roles, or services that should assume this role.",
                    "lateral movement",
                ))
                n += 1
                continue
            own_account = _account_id(p.arn)
            for arn in aws_list:
                if not isinstance(arn, str):
                    continue
                other = _account_id(arn)
                if not arn.startswith("arn:aws:iam::") or other is None or other == own_account:
                    continue
                if ":root" in arn or "/" in arn:
                    findings.append(_finding(
                        "t" + str(n), "medium", "Role trusts an external account",
                        p, f"The trust policy of role {p.name} allows {arn} to assume it. If that account is a third party, a missing external id lets a confused deputy assume the role on a caller's behalf." if not has_condition else f"The trust policy of role {p.name} allows {arn} to assume it under a condition. Confirm the account is yours or a trusted partner.",
                        "Confirm the account is one you control or a trusted partner, and require an external id condition for third party access.",
                        "lateral movement",
                    ))
                    n += 1
            federated = principal.get("Federated") if isinstance(principal, dict) else None
            if federated and not has_condition:
                findings.append(_finding(
                    "t" + str(n), "medium", "Federated trust without a condition",
                    p, f"Role {p.name} trusts a federated identity provider with no condition, so any identity from that provider can assume it.",
                    "Add a condition that limits which federated subjects or audiences may assume the role.",
                    "lateral movement",
                ))
                n += 1
    return findings
