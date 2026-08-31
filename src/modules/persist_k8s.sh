# persist_k8s: a foothold kept across time. Cluster role bindings and role bindings
# bind a controlled subject to a role; a new service account is a fresh identity; an
# admission webhook runs on every future request. Read only.

analyze_persist_k8s() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_k8s";
    [ subjects[] as $s
      | if is_cluster_admin($s) then empty
        else
          ( if can($s;"create";"clusterrolebindings";true) then
              finding("pk-crb"; "high"; "Can create cluster role bindings"; $s;
                ($s.kind + " " + $s.name + " can create cluster role bindings, binding a subject it controls to a powerful role.");
                "Remove create on clusterrolebindings unless this subject administers RBAC."; "persistence") else empty end ),
          ( if can($s;"create";"rolebindings";true) then
              finding("pk-rb"; "medium"; "Can create role bindings across namespaces"; $s;
                ($s.kind + " " + $s.name + " can create role bindings in any namespace, binding a subject it controls to a role and keeping a foothold in that namespace.");
                "Scope rolebinding creation to the namespaces a team owns."; "persistence") else empty end ),
          ( if can($s;"create";"serviceaccounts";true) then
              finding("pk-sa"; "medium"; "Can create service accounts"; $s;
                ($s.kind + " " + $s.name + " can create service accounts, a fresh identity an intruder can stand up, bind, and return through.");
                "Limit create on serviceaccounts to the namespaces and operators that provision workloads."; "persistence") else empty end ),
          ( if (can($s;"create";"mutatingwebhookconfigurations";true) or can($s;"create";"validatingwebhookconfigurations";true)) then
              finding("pk-hook"; "high"; "Can install admission webhooks"; $s;
                ($s.kind + " " + $s.name + " can create admission webhook configurations, which run on every future API request, a durable foothold.");
                "Restrict who can create webhook configurations to cluster operators."; "persistence") else empty end )
        end
    ]' "$1"
}
