"""The tactic checks, organized to mirror S7aba's modules one for one.

S7aba runs offence in six families, recon, privesc, persist, lateral, exfil, and
cleanup. Raqib reads the same account for the defensive side of each: the exposure
that lets that tactic work, and the change that closes it.
"""

from raqib.checks.common import _finding, _principal_label, _account_id, _as_list
from raqib.checks.recon import check_reconnaissance
from raqib.checks.privesc import (
    PRIVESC_METHODS, check_privilege_escalation, check_wildcards,
    _wild_services, _boundary_note, _lower,
)
from raqib.checks.persist import check_persistence
from raqib.checks.lateral import check_trust
from raqib.checks.exfil import check_exfiltration
from raqib.checks.cleanup import TAMPER_GROUPS, check_log_tampering
from raqib.checks.techniques import _technique_for, apply_techniques

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run(acct):
    """Run every tactic check and return the findings, ordered by severity."""
    findings = []
    findings += check_reconnaissance(acct)
    findings += check_privilege_escalation(acct)
    findings += check_wildcards(acct)
    findings += check_persistence(acct)
    findings += check_trust(acct)
    findings += check_exfiltration(acct)
    findings += check_log_tampering(acct)
    apply_techniques(findings)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    return findings


def summarize(findings, acct):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    principals_with = len({f["principal"]["arn"] for f in findings if f["principal"]})
    return {
        "counts": counts,
        "total": len(findings),
        "principals": len(acct.principals),
        "principals_with_findings": principals_with,
    }
