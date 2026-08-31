"""Azure exfiltration checks: the mirror of S7aba's exfil_azure.

The fast path to data in Azure is listing a storage account's keys, which opens every
blob in it, or reading Key Vault secrets. Both are permissions in the export.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p):
            continue
        caps = []
        if acct.allows(p, "microsoft.storage/storageaccounts/listkeys/action"):
            caps.append("list storage account keys, which opens every blob and file in the account")
        if acct.allows_data(p, "microsoft.keyvault/vaults/secrets/getsecret/action"):
            caps.append("read Key Vault secret values")
        if acct.allows_data(p, "microsoft.storage/storageaccounts/blobservices/containers/blobs/read"):
            caps.append("read blob contents")
        if not caps:
            continue
        joined = caps[0] if len(caps) == 1 else ", ".join(caps[:-1]) + ", and " + caps[-1]
        findings.append(_finding("xz" + str(n), "high", "Can read data broadly", p,
            f"{_principal_label(p)} can {joined}. An intruder holding this principal would use it to pull data out.",
            "Scope storage and Key Vault access to the specific accounts and vaults the principal needs.",
            "exfiltration"))
        n += 1
    return findings
