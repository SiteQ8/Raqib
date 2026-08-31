analyze_privesc_azure() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_azure";
    [ principals[] as $p
      | if is_owner($p) then
          finding("kz-own"; "critical"; "Owner or a wildcard role"; $p;
            ($p.name + " holds Owner or a role that allows every action, full control of everything in scope.");
            "Replace Owner with a role scoped to what this principal needs."; "privilege escalation")
        else
          ( if allows($p; "microsoft.authorization/roleassignments/write") then
              finding("kz-grant"; "high"; "Can grant itself any role"; $p;
                ($p.name + " can write role assignments, so it can assign itself Owner.");
                "Remove Microsoft.Authorization/roleAssignments/write or limit it to a narrow scope under review."; "privilege escalation")
            else empty end ),
          ( if allows($p; "microsoft.authorization/elevateaccess/action") then
              finding("kz-elev"; "high"; "Can elevate to tenant root access"; $p;
                ($p.name + " can call elevateAccess, which grants User Access Administrator at the tenant root.");
                "Remove the elevateAccess permission from this principal."; "privilege escalation")
            else empty end )
        end
    ]' "$1"
}
