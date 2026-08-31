"""Azure reconnaissance checks: the mirror of S7aba's recon_azure.

Reader at a subscription or the management group root hands an attacker a map of the
whole estate, and the ability to read role assignments shows who holds what.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p):
            continue
        if acct.has_role(p, "Reader") and p.broadest_scope_rank >= 4:
            findings.append(_finding("rz" + str(n), "low", "Reader across the management group", p,
                f"{_principal_label(p)} can read every resource under a management group, a full map of the estate.",
                "Grant Reader at the narrowest scope a task needs.",
                "reconnaissance"))
            n += 1
        elif acct.allows(p, "microsoft.authorization/roleassignments/read") and p.broadest_scope_rank >= 3:
            findings.append(_finding("rz" + str(n), "low", "Can read all role assignments", p,
                f"{_principal_label(p)} can list who holds which role across a subscription, enough to plan a path.",
                "Limit read of role assignments where it is not needed.",
                "reconnaissance"))
            n += 1
    return findings
