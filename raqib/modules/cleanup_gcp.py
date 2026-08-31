"""GCP anti forensics checks: the mirror of S7aba's cleanup_gcp.

The record in GCP is Cloud Logging, the sinks that route it, and the alerting on top.
Deleting sinks or logs, redirecting a sink, or deleting alert policies all cut off
what would show an intrusion. Read only, never calls GCP.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p) or p.is_public:
            continue
        caps = []
        if acct.has_permission(p, "logging.sinks.delete") or acct.has_permission(p, "logging.logs.delete"):
            caps.append("delete log sinks or logs")
        if acct.has_permission(p, "logging.sinks.update"):
            caps.append("redirect log routing by updating a sink")
        if acct.has_permission(p, "monitoring.alertpolicies.delete"):
            caps.append("delete alerting policies so nothing fires")
        if not caps:
            continue
        joined = caps[0] if len(caps) == 1 else ", ".join(caps[:-1]) + ", and " + caps[-1]
        findings.append(_finding("eg" + str(n), "high", "Can weaken the audit trail", p,
            f"{_principal_label(p)} can {joined}, which is how an intruder stops or erases the record of what they did.",
            "Remove roles/logging.admin and roles/monitoring.admin from principals that do not run them, and route audit logs to a sink another team controls.",
            "defense evasion"))
        n += 1
    return findings
