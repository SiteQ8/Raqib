"""Kubernetes exfiltration checks: the mirror of S7aba's exfil_k8s.

Config maps and secrets hold data and credentials; pod logs leak secrets, tokens, and
data. A subject that can read these cluster wide can pull that data out. Secret reading
is also a lateral route, so a subject that can only read secrets is left to that check.
Read only, never calls the cluster.
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
        if acct.can(p, "get", "pods/log", cluster_wide_only=True):
            caps.append("read pod logs, which leak secrets, tokens, and data")
        if not caps:
            continue
        # secret reading is also reported by lateral movement; a subject that can only
        # read secrets is left to that check, to avoid a duplicate on the same subject
        if caps == ["read every secret in the cluster"]:
            continue
        joined = caps[0] if len(caps) == 1 else ", ".join(caps[:-1]) + ", and " + caps[-1]
        findings.append(_finding("xk" + str(n), "medium", "Can read cluster data broadly", p,
            f"{p.kind} {p.name} can {joined}, across every namespace.",
            "Scope config map, secret, and log access to the namespace a workload needs.",
            "exfiltration"))
        n += 1
    return findings
