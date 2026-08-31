"""GCP exfiltration checks: the mirror of S7aba's exfil_gcp.

Data in GCP sits in Cloud Storage, Secret Manager, and BigQuery. A member that can
read across any of them broadly can pull data out.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p) or p.is_public:
            continue
        caps = []
        if acct.has_permission(p, "secretmanager.versions.access"):
            caps.append("read secrets in Secret Manager")
        if acct.has_permission(p, "storage.objects.get"):
            caps.append("read objects in Cloud Storage")
        if acct.has_permission(p, "bigquery.tables.getdata"):
            caps.append("read BigQuery table data")
        if not caps:
            continue
        joined = caps[0] if len(caps) == 1 else ", ".join(caps[:-1]) + ", and " + caps[-1]
        sev = "high" if any("secret" in c or "Storage" in c for c in caps) else "medium"
        findings.append(_finding("xg" + str(n), sev, "Can read data broadly", p,
            f"{_principal_label(p)} can {joined}, across the project rather than a named resource.",
            "Grant data access on specific buckets, secrets, and datasets, not at the project level.",
            "exfiltration"))
        n += 1
    return findings
