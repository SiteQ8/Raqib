"""Kubernetes privilege escalation checks: the mirror of S7aba's privesc_k8s.

The escalation that matters in Kubernetes is the RBAC verbs that let a subject grant
itself more. escalate writes a role beyond what the writer holds, bind attaches a
subject to a powerful role, and impersonate lets a subject act as another. Reading
secrets cluster wide hands over service account tokens, and creating pods reaches the
node. cluster-admin is all of it at once.
"""

from raqib.lib.common import _finding, _principal_label


def _label(p):
    return _principal_label(p)


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_cluster_admin(p):
            findings.append(_finding("kk" + str(n), "critical", "Holds cluster-admin", p,
                f"{p.kind} {p.name} is bound to a role with every verb on every resource across the cluster, which is full control.",
                "Bind cluster-admin to as few subjects as possible, and give everyone else a role scoped to what they do.",
                "privilege escalation"))
            n += 1
            continue
        if acct.can(p, "escalate", "clusterroles", cluster_wide_only=True) or acct.can(p, "escalate", "roles"):
            findings.append(_finding("kk" + str(n), "high", "Can escalate its own permissions", p,
                f"{p.kind} {p.name} holds the escalate verb on roles, which lets it write a role granting more than it already has.",
                "Remove the escalate verb from this subject's roles.",
                "privilege escalation"))
            n += 1
        if acct.can(p, "bind", "clusterroles", cluster_wide_only=True) or acct.can(p, "bind", "roles"):
            findings.append(_finding("kk" + str(n), "high", "Can bind itself to any role", p,
                f"{p.kind} {p.name} holds the bind verb, which lets it bind itself to a more powerful role such as cluster-admin.",
                "Remove the bind verb from this subject's roles.",
                "privilege escalation"))
            n += 1
        if acct.can(p, "impersonate", "users", cluster_wide_only=True) or acct.can(p, "impersonate", "groups", cluster_wide_only=True) or acct.can(p, "impersonate", "serviceaccounts", cluster_wide_only=True):
            findings.append(_finding("kk" + str(n), "high", "Can impersonate other subjects", p,
                f"{p.kind} {p.name} can impersonate users, groups, or service accounts, acting with their access.",
                "Remove the impersonate verb unless this subject must act on behalf of others.",
                "privilege escalation"))
            n += 1
        if acct.can(p, "create", "pods", cluster_wide_only=True):
            findings.append(_finding("kk" + str(n), "high", "Can create pods cluster wide", p,
                f"{p.kind} {p.name} can create pods in any namespace, which can mount a host path or a powerful service account and reach the node.",
                "Scope pod creation to the namespaces a workload needs, and enforce a pod security standard.",
                "privilege escalation"))
            n += 1
    return findings
