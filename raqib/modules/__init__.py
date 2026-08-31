"""The tactic checks, arranged as a cloud by tactic matrix like S7aba's src/modules.

Every module is named {tactic}_{cloud}. A per cloud runner calls its tactic checks
in order, tags each finding with its technique, and sorts by severity.
"""

from raqib.lib.common import SEVERITY_ORDER
from raqib.lib.techniques import apply_techniques


def _finish(findings):
    apply_techniques(findings)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    return findings


def aws_checks(acct):
    """Run the AWS tactic checks on an already built account and return findings.
    Used where an account is in hand, such as tests and reuse."""
    from raqib.modules import (recon_aws, privesc_aws, persist_aws, lateral_aws,
                               exfil_aws, cleanup_aws)
    f = []
    f += recon_aws.check_reconnaissance(acct)
    f += privesc_aws.check_privilege_escalation(acct)
    f += privesc_aws.check_wildcards(acct)
    f += persist_aws.check_persistence(acct)
    f += lateral_aws.check_trust(acct)
    f += exfil_aws.check_exfiltration(acct)
    f += cleanup_aws.check_log_tampering(acct)
    return _finish(f)


def run_aws(export, credential_report_csv=None, max_key_age_days=90):
    from raqib.models import aws as model
    from raqib.modules import credentials_aws
    acct = model.load(export)
    f = aws_checks(acct)
    if credential_report_csv:
        f = _finish(f + credentials_aws.check(credential_report_csv, max_key_age_days=max_key_age_days))
    return acct, f


def run_azure(export):
    from raqib.models import azure as model
    from raqib.modules import (recon_azure, privesc_azure, persist_azure,
                               lateral_azure, exfil_azure, cleanup_azure)
    acct = model.load(export)
    f = []
    f += recon_azure.check(acct)
    f += privesc_azure.check(acct)
    f += persist_azure.check(acct)
    f += lateral_azure.check(acct)
    f += exfil_azure.check(acct)
    f += cleanup_azure.check(acct)
    return acct, _finish(f)


def run_gcp(export):
    from raqib.models import gcp as model
    from raqib.modules import (recon_gcp, privesc_gcp, persist_gcp,
                               lateral_gcp, exfil_gcp, cleanup_gcp)
    acct = model.load(export)
    f = []
    f += recon_gcp.check(acct)
    f += privesc_gcp.check(acct)
    f += persist_gcp.check(acct)
    f += lateral_gcp.check(acct)
    f += exfil_gcp.check(acct)
    f += cleanup_gcp.check(acct)
    return acct, _finish(f)


def run_k8s(export):
    from raqib.models import k8s as model
    from raqib.modules import (recon_k8s, privesc_k8s, persist_k8s,
                               lateral_k8s, exfil_k8s, cleanup_k8s)
    acct = model.load(export)
    f = []
    f += recon_k8s.check(acct)
    f += privesc_k8s.check(acct)
    f += persist_k8s.check(acct)
    f += lateral_k8s.check(acct)
    f += exfil_k8s.check(acct)
    f += cleanup_k8s.check(acct)
    return acct, _finish(f)


RUNNERS = {"aws": run_aws, "azure": run_azure, "gcp": run_gcp, "k8s": run_k8s}
