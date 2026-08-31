# lateral_k8s: the routes off one workload onto others. Reading secrets across the
# cluster lifts service account tokens from other namespaces. Proxying to the kubelet
# on nodes runs in the pods on that node. Port forwarding opens a tunnel to a pod and
# whatever it can reach. Read only.

analyze_lateral_k8s() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_k8s";
    [ subjects[] as $s
      | if is_cluster_admin($s) then empty
        else
          ( if (can($s;"get";"secrets";true) or can($s;"list";"secrets";true)) then
              finding("lk-sec"; "high"; "Can read secrets across the cluster"; $s;
                ($s.kind + " " + $s.name + " can read secrets in every namespace. Secrets hold service account tokens, a route into other namespaces.");
                "Scope secret access to the namespace a workload runs in."; "lateral movement") else empty end ),
          ( if (can($s;"get";"nodes/proxy";true) or can($s;"create";"nodes/proxy";true)) then
              finding("lk-node"; "high"; "Can reach the kubelet on nodes"; $s;
                ($s.kind + " " + $s.name + " can proxy to the kubelet API on nodes, which runs commands in the pods on a node and reads their logs and mounted tokens, a route off one workload onto others.");
                "Remove nodes/proxy unless a controller genuinely needs it."; "lateral movement") else empty end ),
          ( if can($s;"create";"pods/portforward";true) then
              finding("lk-pf"; "medium"; "Can port forward to pods"; $s;
                ($s.kind + " " + $s.name + " can port forward to pods, opening a tunnel to a pod and any service reachable from it.");
                "Remove pods/portforward unless debugging a namespace requires it."; "lateral movement") else empty end )
        end
    ]' "$1"
}
