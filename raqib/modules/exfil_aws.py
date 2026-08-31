"""Exfiltration checks: the defensive mirror of S7aba's exfil modules.

Once inside, an intruder reaches for the data: secrets, objects, parameters, tables,
and the keys that decrypt them, or they copy a snapshot and share it out of the
account. Every one of those moves rests on a permission, and the permission is in the
IAM export. Raqib flags the principals that can read or move data broadly.

Only an unscoped grant, on resource *, counts here. A principal allowed to read one
named bucket or one secret is doing its job; it is the grant over every bucket, every
secret, or every key that hands an intruder the data at once.

This reads the permission to exfiltrate, which is a different thing from a bucket or
key left open to the public through a resource policy. That resource policy exposure
is not carried in the authorization details and is a separate check to come.
"""

from raqib.lib.common import _finding, _principal_label
from raqib.modules.privesc_aws import _wild_services

# Each capability: a label, the actions that grant it, and how serious it is when
# held over every resource.
DATA_GROUPS = [
    ("read every secret in Secrets Manager", ["secretsmanager:getsecretvalue"], "high"),
    ("read objects in any bucket", ["s3:getobject"], "high"),
    ("make an EBS snapshot public or share it", ["ec2:modifysnapshotattribute"], "high"),
    ("share a database snapshot outside the account", ["rds:modifydbsnapshotattribute", "rds:modifydbclustersnapshotattribute"], "high"),
    ("read every SSM parameter", ["ssm:getparameter", "ssm:getparameters", "ssm:getparametersbypath"], "medium"),
    ("read or export any DynamoDB table", ["dynamodb:scan", "dynamodb:exporttabletopointintime"], "medium"),
    ("decrypt data with any KMS key", ["kms:decrypt"], "medium"),
]


def check_exfiltration(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.admin_statement(p) or p.attached_admin:
            continue
        wild = _wild_services(acct, p)
        capabilities = []
        severity = "medium"
        for label, actions, sev in DATA_GROUPS:
            svc = actions[0].split(":", 1)[0]
            if svc in wild:
                continue  # full control of the service is reported on its own
            # only an unscoped grant, on resource *, is broad data access
            if any(acct.allows(p, a, require_unscoped=True) for a in actions):
                capabilities.append(label)
                if sev == "high":
                    severity = "high"
        if not capabilities:
            continue
        joined = capabilities[0] if len(capabilities) == 1 else ", ".join(capabilities[:-1]) + ", and " + capabilities[-1]
        findings.append(_finding(
            "x" + str(n), severity, "Can read or move data broadly", p,
            f"{_principal_label(p)} can {joined}. An intruder holding this principal would use it to pull data out.",
            "Scope these actions to the specific secrets, buckets, parameters, and tables the principal needs, and never to all of them.",
            "exfiltration",
        ))
        n += 1
    return findings
