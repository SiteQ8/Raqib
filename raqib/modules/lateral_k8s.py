"""Kubernetes lateral movement checks: the mirror of S7aba's lateral_k8s.

Secrets hold service account tokens. A subject that can read secrets across the
cluster can lift a token from another namespace and move there.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_cluster_admin(p):
            continue
        if acct.can(p, "get", "secrets", cluster_wide_only=True) or acct.can(p, "list", "secrets", cluster_wide_only=True):
            findings.append(_finding("lk" + str(n), "high", "Can read secrets across the cluster", p,
                f"{p.kind} {p.name} can read secrets in every namespace. Secrets hold service account tokens, so this is a route into other namespaces and workloads.",
                "Scope secret access to the namespace a workload runs in.",
                "lateral movement"))
            n += 1
    return findings
