"""Raqib: a read only cloud exposure auditor.

Raqib reads an authorization export the account owner produced and reports the moves
an intruder would make after a foothold, gaining more permission, reaching the next
principal, planting persistence, pulling data out, and turning off the logging that
would record it. It covers AWS, Azure, GCP, and Kubernetes, and it never calls a
cloud and never touches an account. You hand it a file, and it reasons about it
offline.
"""

from raqib.lib import detect, common
from raqib import modules

__version__ = "0.10.0"


def audit(export, cloud=None, credential_report_csv=None, max_key_age_days=90):
    """Run the checks for the right cloud against a parsed authorization export.

    cloud is one of aws, azure, gcp, k8s. When left out, Raqib detects it from the
    shape of the export. Returns (findings, summary, account).
    """
    cloud = cloud or detect.detect_cloud(export)
    if cloud is None:
        raise ValueError("could not tell which cloud this export is from; pass the cloud by hand")
    runner = modules.RUNNERS.get(cloud)
    if runner is None:
        raise ValueError("unknown cloud: " + str(cloud))
    if cloud == "aws":
        acct, findings = runner(export, credential_report_csv=credential_report_csv, max_key_age_days=max_key_age_days)
    else:
        acct, findings = runner(export)
    summary = common.summarize(findings, acct)
    summary["cloud"] = cloud
    return findings, summary, acct
