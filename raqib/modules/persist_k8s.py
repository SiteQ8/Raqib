"""Kubernetes persistence checks: the mirror of S7aba's persist_k8s.

A foothold is kept by creating bindings or service accounts, or by installing an
admission webhook that runs on every future request.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_cluster_admin(p):
            continue
        if acct.can(p, "create", "clusterrolebindings", cluster_wide_only=True):
            findings.append(_finding("pk" + str(n), "high", "Can create cluster role bindings", p,
                f"{p.kind} {p.name} can create cluster role bindings, so it can bind a subject it controls to a powerful role and keep access.",
                "Remove create on clusterrolebindings unless this subject administers RBAC.",
                "persistence"))
            n += 1
        if acct.can(p, "create", "mutatingwebhookconfigurations", cluster_wide_only=True) or acct.can(p, "create", "validatingwebhookconfigurations", cluster_wide_only=True):
            findings.append(_finding("pk" + str(n), "high", "Can install admission webhooks", p,
                f"{p.kind} {p.name} can create admission webhook configurations, which run on every future API request and are a durable and stealthy foothold.",
                "Restrict who can create webhook configurations to cluster operators.",
                "persistence"))
            n += 1
    return findings
