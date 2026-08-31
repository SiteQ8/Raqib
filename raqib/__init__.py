"""Raqib: a read only AWS IAM exposure auditor.

It reads an IAM export the account owner produced and reports the privilege
escalation paths, dangerous trust relationships, and wildcard permissions that an
attacker with a foothold would look for, each with the fix that closes it. It never
calls AWS and never touches an account.
"""

from . import model, rules, report, credentials

__version__ = "0.1.0"


def audit(auth_details, credential_report_csv=None, max_key_age_days=90):
    """Run every rule against a parsed authorization details object.

    auth_details is the parsed JSON from get-account-authorization-details.
    credential_report_csv, when given, adds credential findings.
    Returns (findings, summary, account).
    """
    acct = model.load(auth_details)
    findings = rules.run(acct)
    if credential_report_csv:
        findings = findings + credentials.check(credential_report_csv, max_key_age_days=max_key_age_days)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: order.get(f["severity"], 9))
    summary = rules.summarize(findings, acct)
    return findings, summary, acct
