"""Kubernetes exfiltration checks: the mirror of S7aba's exfil_k8s.

Config maps and secrets are where data and credentials sit. A subject that can read
them cluster wide can pull that data out.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_cluster_admin(p):
            continue
        caps = []
        if acct.can(p, "get", "secrets", cluster_wide_only=True) or acct.can(p, "list", "secrets", cluster_wide_only=True):
            caps.append("read every secret in the cluster")
        if acct.can(p, "get", "configmaps", cluster_wide_only=True) or acct.can(p, "list", "configmaps", cluster_wide_only=True):
            caps.append("read every config map")
        if not caps:
            continue
        joined = caps[0] if len(caps) == 1 else caps[0] + " and " + caps[1]
        # secret reading is also reported by lateral movement; keep exfil to config maps
        # unless only secrets matched, to avoid a duplicate on the same subject
        if caps == ["read every secret in the cluster"]:
            continue
        findings.append(_finding("xk" + str(n), "medium", "Can read cluster data broadly", p,
            f"{p.kind} {p.name} can {joined}, across every namespace.",
            "Scope config map and secret access to the namespace a workload needs.",
            "exfiltration"))
        n += 1
    return findings
