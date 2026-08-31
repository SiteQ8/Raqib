# exfil_azure: the permission to read data broadly or carry it out. Listing storage
# keys or minting a SAS opens every blob; reading Key Vault secrets lifts credentials;
# exporting a disk or snapshot downloads a whole image; Cosmos DB keys open every
# database. Read only: it reads the permission, not the data.

analyze_exfil_azure() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_azure";
    [ principals[] as $p
      | if is_owner($p) then empty
        else
          ( [ (if allows($p; "microsoft.storage/storageaccounts/listkeys/action") then "list storage account keys, which opens every blob and file in the account" else empty end),
              (if (allows($p; "microsoft.storage/storageaccounts/listaccountsas/action") or allows($p; "microsoft.storage/storageaccounts/listservicesas/action")) then "mint a SAS token that shares a storage account out" else empty end),
              (if allows_data($p; "microsoft.keyvault/vaults/secrets/getsecret/action") then "read Key Vault secret values" else empty end),
              (if allows_data($p; "microsoft.storage/storageaccounts/blobservices/containers/blobs/read") then "read blob contents" else empty end),
              (if (allows($p; "microsoft.compute/disks/begingetaccess/action") or allows($p; "microsoft.compute/snapshots/begingetaccess/action")) then "export a disk or snapshot as a downloadable image" else empty end),
              (if (allows($p; "microsoft.documentdb/databaseaccounts/listkeys/action") or allows($p; "microsoft.documentdb/databaseaccounts/listconnectionstrings/action")) then "read Cosmos DB keys, which open every database in the account" else empty end) ] ) as $caps
          | if (($caps|length)==0) then empty
            else ( if ($caps|length)==1 then $caps[0] else ($caps[:-1]|join(", ")) + ", and " + $caps[-1] end ) as $joined
              | finding("xz0"; "high"; "Can read data broadly"; $p;
                  ($p.name + " can " + $joined + ". An intruder holding this principal would use it to pull data out.");
                  "Scope storage, Key Vault, disk, and database access to the specific resources the principal needs."; "exfiltration")
            end
        end
    ]' "$1"
}
