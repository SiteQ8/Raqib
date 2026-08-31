"""Azure lateral movement checks: the mirror of S7aba's lateral_azure.

A single identity that reaches across the tenant is a bridge an attacker crosses. A
service principal with a role at a subscription or the management group root reaches
every resource under it. A principal with roles in more than one subscription reaches
across those subscriptions. Read only, never calls Azure.
"""

import re

from raqib.lib.common import _finding, _principal_label

_SUB = re.compile(r"/subscriptions/([^/]+)")


def _subs(principal):
    out = set()
    for assignment in principal.assignments:
        m = _SUB.search((assignment[4] or "").lower())
        if m:
            out.add(m.group(1))
    return out


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p):
            continue
        if p.kind == "ServicePrincipal" and p.broadest_scope_rank >= 3 and acct.allows(p, "microsoft.compute/virtualmachines/read"):
            findings.append(_finding("lz" + str(n), "medium", "Service principal with broad reach", p,
                f"{_principal_label(p)} is a service principal with a role across a subscription or higher. If its secret leaks, that reach is an attacker's to use.",
                "Scope the service principal to the resource groups it needs, and rotate its credentials.",
                "lateral movement"))
            n += 1
        subs = _subs(p)
        if len(subs) >= 2:
            findings.append(_finding("lz" + str(n), "medium", "Principal spans multiple subscriptions", p,
                f"{_principal_label(p)} holds roles in more than one subscription ({', '.join(sorted(subs))}). One compromised identity reaches across those subscriptions.",
                "Confirm this identity needs access in every subscription, and split its roles per subscription where you can.",
                "lateral movement"))
            n += 1
    return findings
