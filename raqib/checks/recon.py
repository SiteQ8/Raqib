"""Reconnaissance checks: the defensive mirror of S7aba's recon modules.

Before doing anything else, an intruder maps what they landed in: who the principals
are, what they can do, and where the data sits. That mapping runs on read and list
permissions. Raqib flags the grants that hand an attacker the whole picture at once,
most of all the one call that dumps the entire IAM configuration, which is the same
export Raqib itself reads.
"""

from raqib.checks.common import _finding, _principal_label
from raqib.checks.privesc import _wild_services


def check_reconnaissance(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.admin_statement(p) or p.attached_admin:
            continue
        wild = _wild_services(acct, p)
        if "iam" in wild or "*" in wild:
            continue  # full IAM control is reported as escalation, not read only recon

        if acct.allows(p, "iam:getaccountauthorizationdetails"):
            findings.append(_finding(
                "r" + str(n), "medium", "Can export the entire IAM configuration", p,
                f"{_principal_label(p)} can call iam:GetAccountAuthorizationDetails, which returns every user, role, group, and policy in one response. It is the first thing an intruder pulls to plan a path, the same export this report is built from.",
                "Limit this action to the small set of principals that audit IAM, and watch for it in the trail.",
                "reconnaissance",
            ))
            n += 1
        elif acct.has_all(p, ["iam:listusers", "iam:listroles", "iam:listpolicies"]):
            findings.append(_finding(
                "r" + str(n), "low", "Can enumerate identities and policies", p,
                f"{_principal_label(p)} can list the account's users, roles, and policies, enough to map who holds what before choosing a target.",
                "Grant IAM read access only where a task needs it.",
                "reconnaissance",
            ))
            n += 1
    return findings
