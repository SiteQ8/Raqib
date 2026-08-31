"""Azure exfiltration checks: the mirror of S7aba's exfil_azure.

The fast paths to data in Azure: listing a storage account's keys or minting a SAS,
which open every blob; reading Key Vault secrets; exporting a disk or snapshot as a
downloadable image; and reading Cosmos DB keys, which open every database. Each is a
permission in the export. Read only, never calls Azure.
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
        if acct.allows(p, "microsoft.storage/storageaccounts/listaccountsas/action") or acct.allows(p, "microsoft.storage/storageaccounts/listservicesas/action"):
            caps.append("mint a SAS token that shares a storage account out")
        if acct.allows_data(p, "microsoft.keyvault/vaults/secrets/getsecret/action"):
            caps.append("read Key Vault secret values")
        if acct.allows_data(p, "microsoft.storage/storageaccounts/blobservices/containers/blobs/read"):
            caps.append("read blob contents")
        if acct.allows(p, "microsoft.compute/disks/begingetaccess/action") or acct.allows(p, "microsoft.compute/snapshots/begingetaccess/action"):
            caps.append("export a disk or snapshot as a downloadable image")
        if acct.allows(p, "microsoft.documentdb/databaseaccounts/listkeys/action") or acct.allows(p, "microsoft.documentdb/databaseaccounts/listconnectionstrings/action"):
            caps.append("read Cosmos DB keys, which open every database in the account")
        if not caps:
            continue
        joined = caps[0] if len(caps) == 1 else ", ".join(caps[:-1]) + ", and " + caps[-1]
        findings.append(_finding("xz" + str(n), "high", "Can read data broadly", p,
            f"{_principal_label(p)} can {joined}. An intruder holding this principal would use it to pull data out.",
            "Scope storage, Key Vault, disk, and database access to the specific resources the principal needs.",
            "exfiltration"))
        n += 1
    return findings
