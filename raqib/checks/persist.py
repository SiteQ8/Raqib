"""Persistence checks: the defensive mirror of S7aba's persist modules.

Having gained access, an intruder wants to keep it, so they plant something durable:
a new user with its own keys, a fresh role they control, a second access key on an
existing user. Raqib flags the principals that can create a new identity and hand it
access, the toolkit for a back door that outlives the first foothold.

A second active access key on an existing user is flagged from the credential report,
which is where that fact lives.
"""

from raqib.checks.common import _finding, _principal_label
from raqib.checks.privesc import _wild_services


def check_persistence(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.admin_statement(p) or p.attached_admin:
            continue
        wild = _wild_services(acct, p)
        if "iam" in wild or "*" in wild:
            continue  # full IAM control is already reported as escalation

        can_create_user = acct.allows(p, "iam:createuser")
        can_grant = (acct.allows(p, "iam:createaccesskey") or acct.allows(p, "iam:attachuserpolicy")
                     or acct.allows(p, "iam:putuserpolicy"))
        can_create_role = acct.allows(p, "iam:createrole") and (
            acct.allows(p, "iam:attachrolepolicy") or acct.allows(p, "iam:putrolepolicy"))

        if can_create_user and can_grant:
            findings.append(_finding(
                "p" + str(n), "high", "Can plant a back door user", p,
                f"{_principal_label(p)} can create a new IAM user and give it credentials or permissions. That is a durable foothold an intruder can leave behind, separate from the account they first took.",
                "Remove the ability to create users, or gate it behind a review, and alert on new user creation.",
                "persistence",
            ))
            n += 1
        elif can_create_user:
            findings.append(_finding(
                "p" + str(n), "medium", "Can create IAM users", p,
                f"{_principal_label(p)} can create IAM users. On its own that is limited, but paired with a way to grant access it becomes a back door.",
                "Limit iam:CreateUser to the principals that provision identities, and watch for new users.",
                "persistence",
            ))
            n += 1

        if can_create_role:
            findings.append(_finding(
                "p" + str(n), "medium", "Can create a role and grant it permissions", p,
                f"{_principal_label(p)} can create a new role and attach permissions to it, which an intruder can use to stand up a role they control and return to.",
                "Limit role creation, and require that new roles carry a permissions boundary.",
                "persistence",
            ))
            n += 1
    return findings
