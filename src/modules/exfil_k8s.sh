analyze_exfil_k8s() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_k8s";
    [ subjects[] as $s
      | if is_cluster_admin($s) then empty
        else
          (can($s;"get";"configmaps";true) or can($s;"list";"configmaps";true)) as $cfg
          | if $cfg then
              finding("xk0"; "medium"; "Can read cluster data broadly"; $s;
                ($s.kind + " " + $s.name + " can read every config map across the cluster.");
                "Scope config map access to the namespace a workload needs."; "exfiltration")
            else empty end
        end
    ]' "$1"
}
