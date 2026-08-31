# model_k8s.jq -- resolve a Kubernetes RBAC export (a List of Roles, ClusterRoles, and
# their bindings) into subjects with their rules, marking cluster wide grants. Read only.

def as_array(x): if x == null then [] elif (x|type)=="array" then x else [x] end;
def has_star($xs; $t): (($xs|index("*")) != null) or (($xs|index($t)) != null);

# collect roles: key "cluster/NAME" for ClusterRole, "NS/NAME" for Role
def roles_map:
  reduce (.items[]?) as $it ({};
    ($it.kind // "") as $k
    | if $k == "ClusterRole" then . + { ("cluster/" + ($it.metadata.name // "")): (as_array($it.rules)) }
      elif $k == "Role" then . + { (($it.metadata.namespace // "") + "/" + ($it.metadata.name // "")): (as_array($it.rules)) }
      else . end );

def subjects:
  roles_map as $roles
  | reduce (.items[]?) as $it ({};
      ($it.kind // "") as $k
      | if ($k == "ClusterRoleBinding" or $k == "RoleBinding") then
          ($k == "ClusterRoleBinding") as $cw
          | ($it.roleRef // {}) as $ref
          | ($it.metadata.namespace // "") as $bns
          | ( if ($ref.kind == "ClusterRole") then ($roles[("cluster/" + ($ref.name // ""))] // [])
              else ($roles[($bns + "/" + ($ref.name // ""))] // []) end ) as $rules
          | reduce (as_array($it.subjects)[]) as $s (.;
              ($s.kind + "|" + $s.name + "|" + ($s.namespace // "")) as $key
              | .[$key] += {
                  kind: $s.kind, name: $s.name, namespace: ($s.namespace // null),
                  arn: ($s.kind + ":" + (if $s.namespace then $s.namespace + "/" else "" end) + $s.name),
                  rules: [ $rules[] | {verbs: (as_array(.verbs)), resources: (as_array(.resources)),
                                       apiGroups: (as_array(.apiGroups)), resourceNames: (as_array(.resourceNames)),
                                       cluster_wide: $cw} ]
                }
            )
        else . end )
  | [ .[] ];

# can the subject do verb on resource? cluster_wide_only limits to cluster wide grants,
# and a rule pinned to named objects is not the broad grant we flag.
def can($s; $verb; $resource; $cwonly):
  any($s.rules[];
    ((.cluster_wide) or ($cwonly | not))
    and ((.resourceNames | length) == 0)
    and has_star(.verbs; $verb) and has_star(.resources; $resource));

def is_cluster_admin($s):
  any($s.rules[]; .cluster_wide and (.verbs|index("*")) and (.resources|index("*")) and (.apiGroups|index("*")));

def principal_ref($s): { kind: $s.kind, name: $s.name, arn: $s.arn };
def finding($id; $sev; $title; $s; $detail; $fix; $tactic):
  { id:$id, severity:$sev, title:$title, principal:principal_ref($s), detail:$detail, fix:$fix, tactic:$tactic };
