"""GCP privilege escalation checks: the mirror of S7aba's privesc_gcp.

The escalation that matters in GCP is control of the project IAM policy and the
ability to act as a service account. setIamPolicy lets a member grant itself Owner.
Impersonating a service account, or creating a key for one, borrows its access.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p):
            findings.append(_finding("kg" + str(n), "critical", "Owner of the project", p,
                f"{_principal_label(p)} holds roles/owner, full control of the project including its IAM policy.",
                "Replace Owner with roles scoped to what this member needs, and keep Owner to a small, monitored set.",
                "privilege escalation"))
            n += 1
            continue
        if acct.has_permission(p, "resourcemanager.projects.setiampolicy"):
            findings.append(_finding("kg" + str(n), "high", "Can rewrite the project IAM policy", p,
                f"{_principal_label(p)} can set the project IAM policy, so it can grant itself Owner and take full control.",
                "Remove the setIamPolicy permission, granted by roles such as Owner, Security Admin, or Project IAM Admin, unless this member administers IAM.",
                "privilege escalation"))
            n += 1
        if acct.has_permission(p, "iam.serviceaccounts.getaccesstoken"):
            findings.append(_finding("kg" + str(n), "high", "Can impersonate service accounts", p,
                f"{_principal_label(p)} can mint access tokens for service accounts, borrowing the access of a more powerful one.",
                "Remove roles/iam.serviceAccountTokenCreator unless this member must impersonate a specific service account.",
                "privilege escalation"))
            n += 1
        elif acct.has_permission(p, "iam.serviceaccounts.actas"):
            findings.append(_finding("kg" + str(n), "medium", "Can act as service accounts", p,
                f"{_principal_label(p)} can attach a service account to a resource it creates and run as that account. Paired with deploy access it becomes escalation.",
                "Grant roles/iam.serviceAccountUser only on the specific service accounts a task needs.",
                "privilege escalation"))
            n += 1
    return findings
