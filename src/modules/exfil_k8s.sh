# exfil_k8s: reading data across the cluster. Config maps and secrets hold data and
# credentials; pod logs leak secrets, tokens, and data. Secret reading is also a
# lateral route, so a subject that can only read secrets is left to that check. Read only.

analyze_exfil_k8s() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_k8s";
    [ subjects[] as $s
      | if is_cluster_admin($s) then empty
        else
          ( [ (if (can($s;"get";"secrets";true) or can($s;"list";"secrets";true)) then "read every secret in the cluster" else empty end),
              (if (can($s;"get";"configmaps";true) or can($s;"list";"configmaps";true)) then "read every config map" else empty end),
              (if can($s;"get";"pods/log";true) then "read pod logs, which leak secrets, tokens, and data" else empty end) ] ) as $caps
          | if (($caps|length)==0) then empty
            elif ($caps == ["read every secret in the cluster"]) then empty
            else ( if ($caps|length)==1 then $caps[0] else ($caps[:-1]|join(", ")) + ", and " + $caps[-1] end ) as $joined
              | finding("xk-data"; "medium"; "Can read cluster data broadly"; $s;
                  ($s.kind + " " + $s.name + " can " + $joined + ", across every namespace.");
                  "Scope config map, secret, and log access to the namespace a workload needs."; "exfiltration")
            end
        end
    ]' "$1"
}
