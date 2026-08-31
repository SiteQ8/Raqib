"""GCP privilege escalation checks: the mirror of S7aba's privesc_gcp.

Beyond Owner and control of the project IAM policy, GCP escalation runs through
service accounts: impersonating or signing as one, acting as one to deploy a
resource that then runs as it (the GCP form of passing a role), rewriting a custom
role granted to the member, and running as a powerful default service account by
starting a build or a deployment. Read only, never calls GCP.
"""

from raqib.lib.common import _finding, _principal_label

IMPERSONATE = [
    "iam.serviceaccounts.getaccesstoken",
    "iam.serviceaccounts.getopenidtoken",
    "iam.serviceaccounts.signblob",
    "iam.serviceaccounts.signjwt",
    "iam.serviceaccounts.implicitdelegation",
]
DEPLOYS = [
    ("cloudfunctions.functions.create", "a Cloud Function"),
    ("compute.instances.create", "a Compute Engine instance"),
    ("run.services.create", "a Cloud Run service"),
]


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
        if p.is_public:
            continue
        if acct.has_permission(p, "resourcemanager.projects.setiampolicy"):
            findings.append(_finding("kg" + str(n), "high", "Can rewrite the project IAM policy", p,
                f"{_principal_label(p)} can set the project IAM policy, so it can grant itself Owner and take full control.",
                "Remove the setIamPolicy permission, granted by roles such as Owner, Security Admin, or Project IAM Admin, unless this member administers IAM.",
                "privilege escalation"))
            n += 1
        if acct.has_permission(p, "iam.roles.update"):
            findings.append(_finding("kg" + str(n), "high", "Can rewrite a custom role it holds", p,
                f"{_principal_label(p)} can update a custom role, so it can add permissions to a role granted to itself.",
                "Remove roles/iam.roleAdmin unless this member curates custom roles, and keep it off members the role is granted to.",
                "privilege escalation"))
            n += 1
        if any(acct.has_permission(p, x) for x in IMPERSONATE):
            findings.append(_finding("kg" + str(n), "high", "Can impersonate service accounts", p,
                f"{_principal_label(p)} can mint tokens for or sign as a service account, borrowing the access of a more powerful one.",
                "Remove roles/iam.serviceAccountTokenCreator unless this member must impersonate a specific service account.",
                "privilege escalation"))
            n += 1
        if acct.has_permission(p, "iam.serviceaccounts.actas"):
            matched = [(perm, tgt) for perm, tgt in DEPLOYS if acct.has_permission(p, perm)]
            if matched:
                for perm, tgt in matched:
                    findings.append(_finding("kg" + str(n), "high", f"Can deploy {tgt} as a service account", p,
                        f"{_principal_label(p)} can act as a service account and create {tgt}, which then runs with that account permissions. This is the GCP form of passing a role.",
                        "Separate serviceAccountUser from deploy permissions, and grant it only on the specific service accounts a task needs.",
                        "privilege escalation"))
                    n += 1
            else:
                findings.append(_finding("kg" + str(n), "medium", "Can act as service accounts", p,
                    f"{_principal_label(p)} can attach a service account to a resource it creates and run as that account. Paired with deploy access it becomes escalation.",
                    "Grant roles/iam.serviceAccountUser only on the specific service accounts a task needs.",
                    "privilege escalation"))
                n += 1
        if acct.has_permission(p, "cloudbuild.builds.create"):
            findings.append(_finding("kg" + str(n), "high", "Can run a build as the Cloud Build service account", p,
                f"{_principal_label(p)} can start a Cloud Build build, whose steps run as the Cloud Build service account, an Editor on the project by default.",
                "Restrict cloudbuild.builds.create, and lower the Cloud Build service account from Editor to what builds actually need.",
                "privilege escalation"))
            n += 1
        if acct.has_permission(p, "deploymentmanager.deployments.create"):
            findings.append(_finding("kg" + str(n), "high", "Can deploy as the Google APIs service account", p,
                f"{_principal_label(p)} can create a Deployment Manager deployment, which runs as the Google APIs service account, an Editor on the project by default.",
                "Restrict deploymentmanager.deployments.create, and run deployments with a scoped service account.",
                "privilege escalation"))
            n += 1
    return findings
