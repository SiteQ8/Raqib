# recon_k8s: the read that maps the cluster. Listing across the cluster sees every
# workload and namespace; reading the roles and bindings maps who can do what. Read only.

analyze_recon_k8s() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_k8s";
    [ subjects[] as $s
      | if is_cluster_admin($s) then empty
        elif (can($s;"list";"*";true) or can($s;"get";"*";true)) then
          finding("rk-all"; "low"; "Can read across the whole cluster"; $s;
            ($s.kind + " " + $s.name + " can list or get every resource in every namespace, a full map of the cluster.");
            "Scope read access to the namespaces and resource types a subject needs."; "reconnaissance")
        elif (can($s;"list";"clusterroles";true) or can($s;"get";"clusterroles";true) or can($s;"list";"clusterrolebindings";true) or can($s;"list";"roles";true) or can($s;"list";"rolebindings";true)) then
          finding("rk-rbac"; "low"; "Can read the cluster RBAC"; $s;
            ($s.kind + " " + $s.name + " can read the roles and bindings across the cluster, mapping who can do what, the first thing an intruder reads to plan a path.");
            "Limit read of RBAC resources to the subjects that audit access."; "reconnaissance")
        else empty end
    ]' "$1"
}
