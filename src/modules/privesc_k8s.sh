# privesc_k8s: the RBAC verbs and resources that let a subject grant itself more.
# escalate, bind, and impersonate are the classic verbs. Creating pods, or the
# workload controllers that create pods, reaches the node and any mounted service
# account. Exec into a pod takes over its identity. Minting service account tokens
# or self approving a certificate signing request forges a credential. cluster-admin
# is all of it. Read only.

analyze_privesc_k8s() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_k8s";
    def workloads: ["deployments","daemonsets","statefulsets","replicasets","jobs","cronjobs","replicationcontrollers"];
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
                "Scope pod creation to the namespaces a workload needs, and enforce a pod security standard."; "privilege escalation") else empty end ),
          ( if any(workloads[]; . as $r | (can($s;"create";$r;true) or can($s;"update";$r;true))) then
              finding("kk-wl"; "high"; "Can create workloads that run pods"; $s;
                ($s.kind + " " + $s.name + " can create or change workload controllers such as deployments and daemonsets, which spawn pods that can mount a host path or a powerful service account and reach the node.");
                "Scope workload creation to the namespaces a team owns, and enforce a pod security standard."; "privilege escalation") else empty end ),
          ( if (can($s;"create";"pods/exec";true) or can($s;"create";"pods/attach";true)) then
              finding("kk-exec"; "high"; "Can exec into running pods"; $s;
                ($s.kind + " " + $s.name + " can exec into or attach to running pods, taking over a workload and the service account token mounted in it.");
                "Remove exec and attach on pods unless debugging a namespace requires it."; "privilege escalation") else empty end ),
          ( if can($s;"create";"serviceaccounts/token";true) then
              finding("kk-tok"; "high"; "Can mint tokens for service accounts"; $s;
                ($s.kind + " " + $s.name + " can create tokens for service accounts, minting a credential for a more powerful identity.");
                "Remove create on serviceaccounts/token unless this subject issues tokens for a workload."; "privilege escalation") else empty end ),
          ( if (can($s;"create";"certificatesigningrequests";true) and can($s;"update";"certificatesigningrequests/approval";true)) then
              finding("kk-csr"; "high"; "Can issue client certificates to authenticate as anyone"; $s;
                ($s.kind + " " + $s.name + " can create certificate signing requests and approve them, minting a client certificate for any user or group, including one in a privileged group.");
                "Separate creating certificate signing requests from approving them, and keep approval to the control plane."; "privilege escalation") else empty end )
        end
    ]' "$1"
}
