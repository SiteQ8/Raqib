"""GCP persistence checks: the mirror of S7aba's persist_gcp.

The durable foothold in GCP is a service account key: a long lived credential that
keeps working. Creating service accounts, or keys for them, is how an intruder stays.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p) or p.is_public:
            continue
        if acct.has_permission(p, "iam.serviceaccountkeys.create"):
            findings.append(_finding("pg" + str(n), "high", "Can create service account keys", p,
                f"{_principal_label(p)} can create keys for service accounts. A service account key is a long lived credential an intruder can take away and keep using.",
                "Remove roles/iam.serviceAccountKeyAdmin, and prefer short lived credentials over keys.",
                "persistence"))
            n += 1
        elif acct.has_permission(p, "iam.serviceaccounts.create"):
            findings.append(_finding("pg" + str(n), "medium", "Can create service accounts", p,
                f"{_principal_label(p)} can create service accounts, a fresh identity an intruder can stand up and return through.",
                "Limit roles/iam.serviceAccountAdmin to the members that provision identities.",
                "persistence"))
            n += 1
    return findings
