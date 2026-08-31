"""Kubernetes reconnaissance checks: the mirror of S7aba's recon_k8s.

A subject that can list across the cluster sees every workload, config, and namespace,
the map an attacker reads first.
"""

from raqib.lib.common import _finding, _principal_label


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
    return findings
