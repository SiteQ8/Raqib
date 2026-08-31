"""Azure persistence checks: the mirror of S7aba's persist_azure.

A foothold is kept by adding credentials to a service principal or a managed identity,
or by planting a fresh role assignment that outlives the first account.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p):
            continue
        if acct.allows(p, "microsoft.managedidentity/userassignedidentities/write"):
            findings.append(_finding("pz" + str(n), "medium", "Can create managed identities", p,
                f"{_principal_label(p)} can create user assigned managed identities, a durable identity an intruder can attach to compute and return through.",
                "Limit creation of managed identities to the principals that provision them.",
                "persistence"))
            n += 1
        if acct.allows(p, "microsoft.authorization/roleassignments/write"):
            findings.append(_finding("pz" + str(n), "medium", "Can plant a standing role assignment", p,
                f"{_principal_label(p)} can create role assignments, which lets an intruder grant a principal they control lasting access.",
                "Alert on new role assignments and keep this permission narrow.",
                "persistence"))
            n += 1
    return findings
