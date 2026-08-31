# model_azure.jq  -- resolve an Azure export ({roleAssignments, roleDefinitions}) into
# principals with the actions they hold, after notActions, and the broadest scope.
# Read only reasoning.

def as_array(x): if x == null then [] elif (x|type)=="array" then x else [x] end;
def lc(x): [ as_array(x)[] | ascii_downcase ];
def action_regex($p): "^" + ($p | gsub("\\."; "\\.") | gsub("\\*"; ".*")) + "$";
def matches_any($pats; $a): any($pats[]; . as $p | ($a | test(action_regex($p); "i")));

def scope_rank($s):
  ($s // "" | ascii_downcase) as $x
  | if ($x == "/" or $x == "") then 5
    elif ($x | startswith("/providers/microsoft.management/managementgroups")) then 4
    elif ($x | contains("/resourcegroups/")) then 2
    elif (($x | startswith("/subscriptions/")) and (($x | split("/") | length) <= 3)) then 3
    else 1 end;

def builtin_actions($name):
  ($name // "" | ascii_downcase) as $n
  | if $n == "owner" then ["*"]
    elif $n == "contributor" then ["*"]
    elif $n == "user access administrator" then ["*/read","microsoft.authorization/*"]
    elif $n == "reader" then ["*/read"]
    else [] end;

def builtin_name($rdid):
  ($rdid // "" | ascii_downcase) as $l
  | if ($l|contains("8e3af657")) then "Owner"
    elif ($l|contains("b24988ac")) then "Contributor"
    elif ($l|contains("acdd72a7")) then "Reader"
    elif ($l|contains("18d7d88d")) then "User Access Administrator"
    else "" end;

def defs_map:
  reduce (.roleDefinitions[]?) as $d ({};
    ($d.properties // $d) as $pr
    | ($d.id // $d.name // "") as $rid
    | ( [ ($pr.permissions // [])[] | {a:lc(.actions), na:lc(.notActions), da:lc(.dataActions)} ]
        | { a: (map(.a)|add // []), na: (map(.na)|add // []), da: (map(.da)|add // []),
            name: ($pr.roleName // "") } ) as $entry
    | . + { ($rid|ascii_downcase): $entry, ("name:" + ($pr.roleName // "" | ascii_downcase)): $entry });

def principals:
  defs_map as $defs
  | ( reduce (.roleAssignments[]?) as $ra ({};
        ($ra.properties // $ra) as $pr
        | ($pr.principalId // "") as $pid
        | ($pr.principalType // "Unknown") as $ptype
        | ($pr.principalName // $pr.principalDisplayName // $pid) as $pname
        | ($pr.scope // "") as $scope
        | ($pr.roleDefinitionId // "") as $rdid
        | ($pr.roleName // "") as $rname
        | ( $defs[($rdid|ascii_downcase)]
            // $defs[("name:" + ($rname|ascii_downcase))]
            // ( (if $rname != "" then $rname else builtin_name($rdid) end) as $bn
                 | {a: builtin_actions($bn), na: [], da: [], name: $bn} ) ) as $entry
        | .[$pid] += {name:$pname, kind:$ptype, arn:$pid,
                      assignments: [ {name:$entry.name, a:$entry.a, na:$entry.na, da:$entry.da, scope:$scope, rank:scope_rank($scope)} ] } )
      | [ .[] ] )
  | map(. + {broadest: ([ .assignments[].rank ] | max // 0)});

def allows($p; $action):
  ($action|ascii_downcase) as $a
  | any($p.assignments[];
      (any(.na[]; . as $n | ($a|test(action_regex($n);"i"))) | not)
      and any(.a[]; . as $g | ($a|test(action_regex($g);"i"))));

def allows_broad($p; $action):
  ($action|ascii_downcase) as $a
  | any($p.assignments[]; .rank >= 3
      and (any(.na[]; . as $n | ($a|test(action_regex($n);"i"))) | not)
      and any(.a[]; . as $g | ($a|test(action_regex($g);"i"))));

def allows_data($p; $action):
  ($action|ascii_downcase) as $a
  | any($p.assignments[]; any(.da[]; . as $g | ($a|test(action_regex($g);"i"))));

def has_role($p; $name): any($p.assignments[]; (.name|ascii_downcase) == ($name|ascii_downcase));

def is_owner($p):
  any($p.assignments[]; (.name|ascii_downcase) == "owner"
      or (any(.a[]; . == "*") and (any(.na[]; contains("authorization")) | not)));

def principal_ref($p): { kind: $p.kind, name: $p.name, arn: $p.arn };
def finding($id; $sev; $title; $p; $detail; $fix; $tactic):
  { id:$id, severity:$sev, title:$title, principal:principal_ref($p), detail:$detail, fix:$fix, tactic:$tactic };
