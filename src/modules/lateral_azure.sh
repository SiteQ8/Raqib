analyze_lateral_azure() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_azure";
    [ principals[] as $p
      | if is_owner($p) then empty
        elif ($p.kind == "ServicePrincipal" and $p.broadest >= 3 and allows($p; "microsoft.compute/virtualmachines/read")) then
          finding("lz0"; "medium"; "Service principal with broad reach"; $p;
            ($p.name + " is a service principal with a role across a subscription or higher. If its secret leaks, that reach is an attacker to use.");
            "Scope the service principal to the resource groups it needs, and rotate its credentials."; "lateral movement")
        else empty end
    ]' "$1"
}
