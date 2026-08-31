"""Azure anti forensics checks: the mirror of S7aba's cleanup_azure.

The record in Azure is the activity log, diagnostic settings, and the Log Analytics
workspaces they flow to. A principal that can delete those can blind the tenant.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p):
            continue
        caps = []
        if acct.allows(p, "microsoft.insights/diagnosticsettings/delete"):
            caps.append("delete diagnostic settings")
        if acct.allows(p, "microsoft.operationalinsights/workspaces/delete"):
            caps.append("delete Log Analytics workspaces")
        if acct.allows(p, "microsoft.insights/activitylogalerts/delete"):
            caps.append("delete activity log alerts")
        if not caps:
            continue
        joined = caps[0] if len(caps) == 1 else ", ".join(caps[:-1]) + ", and " + caps[-1]
        findings.append(_finding("ez" + str(n), "high", "Can weaken the audit trail", p,
            f"{_principal_label(p)} can {joined}. That is how an intruder reduces or erases the record of what they did.",
            "Remove these delete permissions, and protect logging with an Azure policy so it cannot be turned off in one place.",
            "defense evasion"))
        n += 1
    return findings
