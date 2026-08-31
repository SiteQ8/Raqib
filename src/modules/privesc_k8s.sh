analyze_privesc_k8s() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_k8s";
    [ subjects[] as $s
      | if is_cluster_admin($s) then
          finding("kk-adm"; "critical"; "Holds cluster-admin"; $s;
            ($s.kind + " " + $s.name + " is bound to a role with every verb on every resource across the cluster, full control.");
            "Bind cluster-admin to as few subjects as possible."; "privilege escalation")
        else
          ( if (can($s;"escalate";"clusterroles";true) or can($s;"escalate";"roles";false)) then
              finding("kk-esc"; "high"; "Can escalate its own permissions"; $s;
                ($s.kind + " " + $s.name + " holds the escalate verb on roles, letting it write a role granting more than it has.");
                "Remove the escalate verb from this subject roles."; "privilege escalation") else empty end ),
          ( if (can($s;"bind";"clusterroles";true) or can($s;"bind";"roles";false)) then
              finding("kk-bind"; "high"; "Can bind itself to any role"; $s;
                ($s.kind + " " + $s.name + " holds the bind verb, letting it bind itself to a more powerful role.");
                "Remove the bind verb from this subject roles."; "privilege escalation") else empty end ),
          ( if (can($s;"impersonate";"users";true) or can($s;"impersonate";"groups";true) or can($s;"impersonate";"serviceaccounts";true)) then
              finding("kk-imp"; "high"; "Can impersonate other subjects"; $s;
                ($s.kind + " " + $s.name + " can impersonate users, groups, or service accounts, acting with their access.");
                "Remove the impersonate verb unless acting on behalf of others is required."; "privilege escalation") else empty end ),
          ( if can($s;"create";"pods";true) then
              finding("kk-pod"; "high"; "Can create pods cluster wide"; $s;
                ($s.kind + " " + $s.name + " can create pods in any namespace, which can mount a host path or a powerful service account and reach the node.");
                "Scope pod creation to the namespaces a workload needs, and enforce a pod security standard."; "privilege escalation") else empty end )
        end
    ]' "$1"
}
