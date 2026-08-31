analyze_exfil_azure() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_azure";
    [ principals[] as $p
      | if is_owner($p) then empty
        else
          ( [ (if allows($p; "microsoft.storage/storageaccounts/listkeys/action") then "list storage account keys, which opens every blob and file in the account" else empty end),
              (if allows_data($p; "microsoft.keyvault/vaults/secrets/getsecret/action") then "read Key Vault secret values" else empty end),
              (if allows_data($p; "microsoft.storage/storageaccounts/blobservices/containers/blobs/read") then "read blob contents" else empty end) ] ) as $caps
          | if (($caps|length)==0) then empty
            else ( if ($caps|length)==1 then $caps[0] else ($caps[:-1]|join(", ")) + ", and " + $caps[-1] end ) as $joined
              | finding("xz0"; "high"; "Can read data broadly"; $p;
                  ($p.name + " can " + $joined + ". An intruder holding this principal would pull data out.");
                  "Scope storage and Key Vault access to the specific accounts and vaults the principal needs."; "exfiltration")
            end
        end
    ]' "$1"
}
