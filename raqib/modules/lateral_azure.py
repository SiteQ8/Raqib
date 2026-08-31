"""Azure lateral movement checks: the mirror of S7aba's lateral_azure.

A single principal that holds a role at a subscription or the management group root
reaches every resource under it, and a service principal with that reach is a bridge
an attacker crosses.
"""

from raqib.lib.common import _finding, _principal_label


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
    return findings
