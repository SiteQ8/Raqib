"""Azure persistence checks: the mirror of S7aba's persist_azure.

A foothold is kept with a standing role assignment or a new managed identity, both
durable. A federated identity credential on a managed identity lets an external OIDC
issuer authenticate as it, a modern back door with no secret to rotate. An Automation
account is a durable, scheduled execution surface. Read only, never calls Azure.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p):
            continue
        if acct.allows(p, "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials/write"):
            findings.append(_finding("pz" + str(n), "high", "Can add a federated credential to a managed identity", p,
                f"{_principal_label(p)} can add a federated identity credential to a user assigned managed identity, letting an external OIDC issuer authenticate as that identity with no secret to rotate.",
                "Restrict federatedIdentityCredentials writes, and review the trust of every federated credential.",
                "persistence"))
            n += 1
        if acct.allows(p, "microsoft.managedidentity/userassignedidentities/write"):
            findings.append(_finding("pz" + str(n), "medium", "Can create managed identities", p,
                f"{_principal_label(p)} can create user assigned managed identities, a durable identity an intruder can attach to compute and return through.",
                "Limit creation of managed identities to the principals that provision them.",
                "persistence"))
            n += 1
        if acct.allows(p, "microsoft.automation/automationaccounts/write"):
            findings.append(_finding("pz" + str(n), "medium", "Can create an Automation account", p,
                f"{_principal_label(p)} can create an Automation account, a durable and scheduled execution surface that can run as a managed identity.",
                "Limit who can create Automation accounts, and review their runbooks and identities.",
                "persistence"))
            n += 1
        if acct.allows(p, "microsoft.authorization/roleassignments/write"):
            findings.append(_finding("pz" + str(n), "medium", "Can plant a standing role assignment", p,
                f"{_principal_label(p)} can create role assignments, which lets an intruder grant a principal they control lasting access.",
                "Alert on new role assignments and keep this permission narrow.",
                "persistence"))
            n += 1
    return findings
