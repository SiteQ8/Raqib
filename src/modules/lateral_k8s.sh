analyze_lateral_k8s() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_k8s";
    [ subjects[] as $s
      | if is_cluster_admin($s) then empty
        elif (can($s;"get";"secrets";true) or can($s;"list";"secrets";true)) then
          finding("lk0"; "high"; "Can read secrets across the cluster"; $s;
            ($s.kind + " " + $s.name + " can read secrets in every namespace. Secrets hold service account tokens, a route into other namespaces.");
            "Scope secret access to the namespace a workload runs in."; "lateral movement")
        else empty end
    ]' "$1"
}
