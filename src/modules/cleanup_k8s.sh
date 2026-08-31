analyze_cleanup_k8s() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_k8s";
    [ subjects[] as $s
      | if is_cluster_admin($s) then empty
        else
          ( [ (if can($s;"delete";"events";true) then "delete events, the cluster own record of what happened" else empty end),
              (if (can($s;"delete";"validatingwebhookconfigurations";true) or can($s;"delete";"mutatingwebhookconfigurations";true)) then "delete admission webhook configurations that enforce policy" else empty end) ] ) as $caps
          | if (($caps|length)==0) then empty
            else ( if ($caps|length)==1 then $caps[0] else $caps[0] + " and " + $caps[1] end ) as $joined
              | finding("ek0"; "medium"; "Can weaken what records the cluster"; $s;
                  ($s.kind + " " + $s.name + " can " + $joined + ".");
                  "Remove delete on events and webhook configurations from workloads, and ship audit logs off the cluster."; "defense evasion")
            end
        end
    ]' "$1"
}
