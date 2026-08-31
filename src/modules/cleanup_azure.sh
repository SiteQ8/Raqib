analyze_cleanup_azure() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_azure";
    [ principals[] as $p
      | if is_owner($p) then empty
        else
          ( [ (if allows($p; "microsoft.insights/diagnosticsettings/delete") then "delete diagnostic settings" else empty end),
              (if allows($p; "microsoft.operationalinsights/workspaces/delete") then "delete Log Analytics workspaces" else empty end),
              (if allows($p; "microsoft.insights/activitylogalerts/delete") then "delete activity log alerts" else empty end) ] ) as $caps
          | if (($caps|length)==0) then empty
            else ( if ($caps|length)==1 then $caps[0] else ($caps[:-1]|join(", ")) + ", and " + $caps[-1] end ) as $joined
              | finding("ez0"; "high"; "Can weaken the audit trail"; $p;
                  ($p.name + " can " + $joined + ". That is how an intruder reduces the record of what they did.");
                  "Remove these delete permissions, and protect logging with an Azure policy."; "defense evasion")
            end
        end
    ]' "$1"
}
