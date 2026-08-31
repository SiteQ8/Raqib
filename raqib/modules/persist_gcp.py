"""GCP persistence checks: the mirror of S7aba's persist_gcp.

A durable foothold in GCP is a service account key, a long lived credential that keeps
working, or a fresh service account. Setting the IAM policy on a service account binds
a controlled principal to it as a stealthy back door, and a scheduled job triggers again a
callback on a timer. Read only, never calls GCP.
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
        if acct.has_permission(p, "iam.serviceaccounts.setiampolicy"):
            findings.append(_finding("pg" + str(n), "medium", "Can grant lasting access to a service account", p,
                f"{_principal_label(p)} can set the IAM policy on a service account, binding a principal it controls as a token creator, a stealthy back door into that identity.",
                "Restrict iam.serviceAccounts.setIamPolicy, and review who is bound on high value service accounts.",
                "persistence"))
            n += 1
        if acct.has_permission(p, "cloudscheduler.jobs.create"):
            findings.append(_finding("pg" + str(n), "medium", "Can plant a scheduled job", p,
                f"{_principal_label(p)} can create Cloud Scheduler jobs, a timer an intruder can use to trigger a callback again and return.",
                "Limit cloudscheduler.jobs.create, and review scheduled jobs for unexpected targets.",
                "persistence"))
            n += 1
    return findings
