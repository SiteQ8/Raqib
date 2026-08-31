"""Anti forensics checks: the defensive mirror of S7aba's cleanup modules.

Finds principals, beyond the administrators already flagged, that can stop or delete
the account's own record keeping, the move an intruder makes to erase their tracks.
"""

from raqib.lib.common import _finding, _principal_label

TAMPER_GROUPS = [
    ("stop or delete CloudTrail", ["cloudtrail:stoplogging", "cloudtrail:deletetrail"]),
    ("reconfigure CloudTrail so it records less", ["cloudtrail:updatetrail", "cloudtrail:puteventselectors"]),
    ("stop or delete Config recording", ["config:stopconfigurationrecorder", "config:deleteconfigurationrecorder", "config:deletedeliverychannel"]),
    ("disable or delete GuardDuty", ["guardduty:deletedetector", "guardduty:updatedetector", "guardduty:deletemembers", "guardduty:disassociatemembers"]),
    ("delete CloudWatch log groups", ["logs:deleteloggroup", "logs:deletelogstream"]),
    ("disable Security Hub", ["securityhub:disablesecurityhub", "securityhub:batchdisablestandards"]),
    ("delete an access analyzer", ["accessanalyzer:deleteanalyzer"]),
]


def check_log_tampering(acct):
    """Find principals that can disable or delete the account's audit trail.

    This is the defensive counterpart to an evidence destruction step: before or
    after acting, an intruder turns off what would record them. Knowing who can do
    that, beyond the administrators already flagged, is worth surfacing on its own.
    """
    findings = []
    n = 0
    for p in acct.principals:
        if acct.admin_statement(p) or p.attached_admin:
            continue  # administrators are already reported; this is about narrower grants
        capabilities = []
        unscoped = False
        for label, actions in TAMPER_GROUPS:
            if any(acct.allows(p, a) for a in actions):
                capabilities.append(label)
                if any(acct.allows(p, a, require_unscoped=True) for a in actions):
                    unscoped = True
        if not capabilities:
            continue
        sev = "high" if unscoped else "medium"
        joined = capabilities[0] if len(capabilities) == 1 else ", ".join(capabilities[:-1]) + ", and " + capabilities[-1]
        findings.append(_finding(
            "e" + str(n), sev, "Can weaken the audit trail", p,
            f"{_principal_label(p)} can {joined}. An intruder holding this principal would use it to reduce or erase the record of what they did.",
            "Remove these actions from the principal, and protect logging with an organization policy so a single account cannot turn it off.",
            "defense evasion",
        ))
        n += 1
    return findings
