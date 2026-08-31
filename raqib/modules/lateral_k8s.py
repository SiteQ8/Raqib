"""Kubernetes lateral movement checks: the mirror of S7aba's lateral_k8s.

The routes off one workload onto others. Reading secrets across the cluster lifts
service account tokens from other namespaces. Proxying to the kubelet on nodes runs in
the pods on a node. Port forwarding opens a tunnel to a pod and whatever it can reach.
Read only, never calls the cluster.
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
        if acct.can(p, "get", "nodes/proxy", cluster_wide_only=True) or acct.can(p, "create", "nodes/proxy", cluster_wide_only=True):
            findings.append(_finding("lk" + str(n), "high", "Can reach the kubelet on nodes", p,
                f"{p.kind} {p.name} can proxy to the kubelet API on nodes, which runs commands in the pods on a node and reads their logs and mounted tokens, a route off one workload onto others.",
                "Remove nodes/proxy unless a controller genuinely needs it.",
                "lateral movement"))
            n += 1
        if acct.can(p, "create", "pods/portforward", cluster_wide_only=True):
            findings.append(_finding("lk" + str(n), "medium", "Can port forward to pods", p,
                f"{p.kind} {p.name} can port forward to pods, opening a tunnel to a pod and any service reachable from it.",
                "Remove pods/portforward unless debugging a namespace requires it.",
                "lateral movement"))
            n += 1
    return findings
