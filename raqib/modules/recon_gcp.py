"""GCP reconnaissance checks: the mirror of S7aba's recon_gcp.

Viewer over a project is a full read of every resource in it, the map an attacker
draws before choosing a target.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p) or p.is_public:
            continue
        if acct.has_role(p, "roles/viewer") and not acct.has_permission(p, "resourcemanager.projects.setiampolicy"):
            findings.append(_finding("rg" + str(n), "low", "Viewer over the project", p,
                f"{_principal_label(p)} can read every resource in the project, a full map of what is there.",
                "Grant read access at the narrowest scope a task needs rather than project wide Viewer.",
                "reconnaissance"))
            n += 1
    return findings
