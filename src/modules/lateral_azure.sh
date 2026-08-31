# lateral_azure: a single identity that reaches across the tenant. A service principal
# with a role at a subscription or higher is a bridge if its secret leaks. A principal
# with roles in more than one subscription reaches across those subscriptions. Read only.

analyze_lateral_azure() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_azure";
    def subs($p): [ $p.assignments[].scope | ascii_downcase | select(test("/subscriptions/")) | capture("/subscriptions/(?<s>[^/]+)").s ] | unique;
    [ principals[] as $p
      | if is_owner($p) then empty
        else
          ( if ($p.kind == "ServicePrincipal" and $p.broadest >= 3 and allows($p; "microsoft.compute/virtualmachines/read")) then
              finding("lz-sp"; "medium"; "Service principal with broad reach"; $p;
                ($p.name + " is a service principal with a role across a subscription or higher. If its secret leaks, that reach is an attacker to use.");
                "Scope the service principal to the resource groups it needs, and rotate its credentials."; "lateral movement")
            else empty end ),
          ( if ((subs($p) | length) >= 2) then
              finding("lz-multisub"; "medium"; "Principal spans multiple subscriptions"; $p;
                ($p.name + " holds roles in more than one subscription (" + (subs($p) | join(", ")) + "). One compromised identity reaches across those subscriptions.");
                "Confirm this identity needs access in every subscription, and split its roles per subscription where you can."; "lateral movement")
            else empty end )
        end
    ]' "$1"
}
