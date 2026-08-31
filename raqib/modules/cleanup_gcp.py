"""GCP anti forensics checks: the mirror of S7aba's cleanup_gcp.

The record in GCP is Cloud Logging and the sinks that route it. A member that can
delete sinks or logs can cut off what would show an intrusion.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p) or p.is_public:
            continue
        if acct.has_permission(p, "logging.sinks.delete") or acct.has_permission(p, "logging.logs.delete"):
            findings.append(_finding("eg" + str(n), "high", "Can weaken the audit trail", p,
                f"{_principal_label(p)} can delete log sinks or logs, which is how an intruder stops or erases the record of what they did.",
                "Remove roles/logging.admin from principals that do not run logging, and route audit logs to a sink another team controls.",
                "defense evasion"))
            n += 1
    return findings
