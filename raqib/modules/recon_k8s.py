"""Kubernetes reconnaissance checks: the mirror of S7aba's recon_k8s.

Listing across the cluster sees every workload, config, and namespace. Reading the
roles and bindings maps who can do what. Both are the map an attacker reads first.
Read only, never calls the cluster.
"""

from raqib.lib.common import _finding, _principal_label

RBAC = ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_cluster_admin(p):
            continue
        if acct.can(p, "list", "*", cluster_wide_only=True) or acct.can(p, "get", "*", cluster_wide_only=True):
            findings.append(_finding("rk" + str(n), "low", "Can read across the whole cluster", p,
                f"{p.kind} {p.name} can list or get every resource in every namespace, a full map of the cluster.",
                "Scope read access to the namespaces and resource types a subject needs.",
                "reconnaissance"))
            n += 1
        elif (acct.can(p, "list", "clusterroles", cluster_wide_only=True) or acct.can(p, "get", "clusterroles", cluster_wide_only=True)
              or acct.can(p, "list", "clusterrolebindings", cluster_wide_only=True) or acct.can(p, "list", "roles", cluster_wide_only=True)
              or acct.can(p, "list", "rolebindings", cluster_wide_only=True)):
            findings.append(_finding("rk" + str(n), "low", "Can read the cluster RBAC", p,
                f"{p.kind} {p.name} can read the roles and bindings across the cluster, mapping who can do what, the first thing an intruder reads to plan a path.",
                "Limit read of RBAC resources to the subjects that audit access.",
                "reconnaissance"))
            n += 1
    return findings
