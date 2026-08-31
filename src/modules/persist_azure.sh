analyze_persist_azure() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_azure";
    [ principals[] as $p
      | if is_owner($p) then empty
        else
          ( if allows($p; "microsoft.managedidentity/userassignedidentities/write") then
              finding("pz0"; "medium"; "Can create managed identities"; $p;
                ($p.name + " can create user assigned managed identities, a durable identity an intruder can attach to compute.");
                "Limit creation of managed identities to the principals that provision them."; "persistence")
            else empty end ),
          ( if allows($p; "microsoft.authorization/roleassignments/write") then
              finding("pz1"; "medium"; "Can plant a standing role assignment"; $p;
                ($p.name + " can create role assignments, granting a principal it controls lasting access.");
                "Alert on new role assignments and keep this permission narrow."; "persistence")
            else empty end )
        end
    ]' "$1"
}
