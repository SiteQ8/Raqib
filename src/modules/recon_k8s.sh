analyze_recon_k8s() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_k8s";
    [ subjects[] as $s
      | if is_cluster_admin($s) then empty
        elif (can($s;"list";"*";true) or can($s;"get";"*";true)) then
          finding("rk0"; "low"; "Can read across the whole cluster"; $s;
            ($s.kind + " " + $s.name + " can list or get every resource in every namespace, a full map of the cluster.");
            "Scope read access to the namespaces and resource types a subject needs."; "reconnaissance")
        else empty end
    ]' "$1"
}
