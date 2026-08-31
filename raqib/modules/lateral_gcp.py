"""GCP lateral movement checks: the mirror of S7aba's lateral_gcp.

The bridges an intruder crosses in GCP. A role granted to everyone is an open door. A
default service account with a broad role is a pivot: compromise the compute it is
attached to and inherit that reach. A group with a powerful role is an opaque grant,
its membership is not visible in the IAM policy. Read only, never calls GCP.
"""

import re

from raqib.lib.common import _finding, _principal_label

_DEFAULT_SA = re.compile(r"(-compute@developer\.gserviceaccount\.com|@appspot\.gserviceaccount\.com|@cloudservices\.gserviceaccount\.com)$")


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p):
            continue
        if p.is_public:
            findings.append(_finding("lg" + str(n), "critical", "A role is granted to everyone", p,
                f"The project grants roles to {p.member}, which means anyone on the internet, or anyone with a Google account, holds that access.",
                "Remove allUsers and allAuthenticatedUsers from every binding.",
                "lateral movement"))
            n += 1
            continue
        if _DEFAULT_SA.search(p.member or "") and (acct.has_role(p, "roles/editor") or acct.has_role(p, "roles/owner")):
            findings.append(_finding("lg" + str(n), "high", "A default service account holds a broad role", p,
                f"{_principal_label(p)} is a default service account with Editor or Owner. It is attached to compute by default, so a foothold on a VM or a function inherits this reach.",
                "Remove the broad role from the default service account, run workloads as a dedicated least privilege service account, and disable default service account grants.",
                "lateral movement"))
            n += 1
        if (p.member or "").startswith("group:") and (acct.has_role(p, "roles/owner") or acct.has_role(p, "roles/editor")):
            findings.append(_finding("lg" + str(n), "medium", "A group holds a powerful role", p,
                f"{_principal_label(p)} is a group granted Owner or Editor. The membership is managed outside the project, so who holds this access is not visible in the IAM policy.",
                "Confirm the group membership is controlled and reviewed, and prefer scoped roles over Owner or Editor on a group.",
                "lateral movement"))
            n += 1
    return findings
