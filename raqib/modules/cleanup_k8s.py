"""Kubernetes anti forensics checks: the mirror of S7aba's cleanup_k8s.

Events are the cluster's own record of what happened, and admission webhooks are what
enforces policy. A subject that can delete events, or remove the webhooks, weakens
what would catch an intrusion.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_cluster_admin(p):
            continue
        caps = []
        if acct.can(p, "delete", "events", cluster_wide_only=True):
            caps.append("delete events, the cluster's own record of what happened")
        if acct.can(p, "delete", "validatingwebhookconfigurations", cluster_wide_only=True) or acct.can(p, "delete", "mutatingwebhookconfigurations", cluster_wide_only=True):
            caps.append("delete admission webhook configurations that enforce policy")
        if not caps:
            continue
        joined = caps[0] if len(caps) == 1 else caps[0] + " and " + caps[1]
        findings.append(_finding("ek" + str(n), "medium", "Can weaken what records the cluster", p,
            f"{p.kind} {p.name} can {joined}.",
            "Remove delete on events and webhook configurations from workloads, and ship audit logs off the cluster.",
            "defense evasion"))
        n += 1
    return findings
