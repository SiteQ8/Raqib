analyze_recon_azure() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_azure";
    [ principals[] as $p
      | if is_owner($p) then empty
        elif (has_role($p; "Reader") and $p.broadest >= 4) then
          finding("rz0"; "low"; "Reader across the management group"; $p;
            ($p.name + " can read every resource under a management group, a full map of the estate.");
            "Grant Reader at the narrowest scope a task needs."; "reconnaissance")
        elif (allows_broad($p; "microsoft.authorization/roleassignments/read")) then
          finding("rz1"; "low"; "Can read all role assignments"; $p;
            ($p.name + " can list who holds which role across a subscription.");
            "Limit read of role assignments where it is not needed."; "reconnaissance")
        else empty end
    ]' "$1"
}
