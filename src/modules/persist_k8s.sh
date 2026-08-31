analyze_persist_k8s() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_k8s";
    [ subjects[] as $s
      | if is_cluster_admin($s) then empty
        else
          ( if can($s;"create";"clusterrolebindings";true) then
              finding("pk0"; "high"; "Can create cluster role bindings"; $s;
                ($s.kind + " " + $s.name + " can create cluster role bindings, binding a subject it controls to a powerful role.");
                "Remove create on clusterrolebindings unless this subject administers RBAC."; "persistence") else empty end ),
          ( if (can($s;"create";"mutatingwebhookconfigurations";true) or can($s;"create";"validatingwebhookconfigurations";true)) then
              finding("pk1"; "high"; "Can install admission webhooks"; $s;
                ($s.kind + " " + $s.name + " can create admission webhook configurations, which run on every future API request, a durable foothold.");
                "Restrict who can create webhook configurations to cluster operators."; "persistence") else empty end )
        end
    ]' "$1"
}
