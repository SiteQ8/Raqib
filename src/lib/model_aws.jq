# model_aws.jq
# Resolve an AWS get-account-authorization-details export into principals with their
# effective policy statements, so a check can ask whether a principal is allowed an
# action. This reasons over the export only. It is read only.

def as_array(x): if x == null then [] elif (x|type) == "array" then x else [x] end;
def lc_list(x): [ as_array(x)[] | ascii_downcase ];

# an IAM action pattern to an anchored regex. action names are regex safe apart from
# the wildcard, so only the dot and star need care.
def action_regex($p):
  "^" + ($p | gsub("\\."; "\\.") | gsub("\\*"; ".*")) + "$";

def matches_any($patterns; $action):
  any($patterns[]; . as $p | ($action | test(action_regex($p); "i")));

def norm_stmt:
  {
    effect: (.Effect // "Allow"),
    act:    (if has("Action") then lc_list(.Action) else [] end),
    notact: (if has("NotAction") then lc_list(.NotAction) else [] end),
    res:    (if has("Resource") then as_array(.Resource) else [] end),
    notres: (if has("NotResource") then as_array(.NotResource) else [] end)
  };

def statements_of($doc): as_array($doc.Statement) | map(norm_stmt);

def stmt_hits_action($s; $action):
  if ($s.act|length) > 0 then matches_any($s.act; $action)
  elif ($s.notact|length) > 0 then (matches_any($s.notact; $action) | not)
  else false end;

def stmt_unscoped($s): ($s.res | index("*")) != null;
def stmt_any_resource($s): (($s.res|length) > 0) or (($s.notres|length) > 0);

# does the set of statements allow this action? unscoped means only a grant on "*".
def allows($stmts; $action; $unscoped):
  (any($stmts[]; .effect == "Deny" and stmt_hits_action(.; $action))) as $denied
  | if $denied then false
    else any($stmts[]; .effect == "Allow" and stmt_hits_action(.; $action)
              and (if $unscoped then stmt_unscoped(.) else (stmt_unscoped(.) or stmt_any_resource(.)) end))
    end;

def allows($stmts; $action): allows($stmts; $action; false);

# does the principal hold every action in the list (each on any resource)?
def has_all($stmts; $actions): all($actions[]; . as $a | allows($stmts; $a));

# --- resolving the export into principals -------------------------------------

def managed_map:
  reduce (.Policies[]?) as $p ({};
    . + { ($p.Arn): ( ($p.PolicyVersionList // [])
                      | map(select(.IsDefaultVersion == true))
                      | (.[0].Document // {Statement: []}) ) });

def group_map:
  reduce (.GroupDetailList[]?) as $g ({}; . + { ($g.GroupName): $g });

def admin_arns:
  ["arn:aws:iam::aws:policy/administratoraccess"];

def attached_is_admin($attached):
  any($attached[]?; (.PolicyArn // "" | ascii_downcase) as $a | (admin_arns | index($a)) != null);

def group_stmts($g; $managed):
  ( [ $g.GroupPolicyList[]?.PolicyDocument | statements_of(.) ] | add // [] )
  + ( [ $g.AttachedManagedPolicies[]?.PolicyArn | statements_of($managed[.] // {Statement: []}) ] | add // [] );

def principals:
  managed_map as $managed
  | group_map as $groups
  | (
      [ .UserDetailList[]? as $u
        | ( ( [ $u.UserPolicyList[]?.PolicyDocument | statements_of(.) ] | add // [] )
            + ( [ $u.AttachedManagedPolicies[]?.PolicyArn | statements_of($managed[.] // {Statement: []}) ] | add // [] )
            + ( [ $u.GroupList[]? as $gn | ($groups[$gn] // {}) | group_stmts(.; $managed) ] | add // [] ) ) as $stmts
        | ( ($u.PermissionsBoundary.PermissionsBoundaryArn // null) as $barn
            | if $barn == null then null else statements_of($managed[$barn] // {Statement: []}) end ) as $bstmts
        | {
            kind: "user",
            name: $u.UserName,
            arn: $u.Arn,
            stmts: $stmts,
            boundary: $bstmts,
            attached_admin: attached_is_admin($u.AttachedManagedPolicies // []),
            trust: null
          } ]
      +
      [ .RoleDetailList[]? as $r
        | ( ( [ $r.RolePolicyList[]?.PolicyDocument | statements_of(.) ] | add // [] )
            + ( [ $r.AttachedManagedPolicies[]?.PolicyArn | statements_of($managed[.] // {Statement: []}) ] | add // [] ) ) as $stmts
        | {
            kind: "role",
            name: $r.RoleName,
            arn: $r.Arn,
            stmts: $stmts,
            boundary: null,
            attached_admin: attached_is_admin($r.AttachedManagedPolicies // []),
            trust: ($r.AssumeRolePolicyDocument // null)
          } ]
    );

# a permissions boundary caps a principal. true when there is no boundary, or the
# boundary would still allow the action.
def boundary_allows($p; $action):
  if ($p.boundary == null) then true else allows($p.boundary; $action) end;

# is this principal an administrator (allow * on *) ?
def is_admin($p): allows($p.stmts; "*"; true) or $p.attached_admin;

# the account id out of an arn like arn:aws:iam::1234:user/x
def account_of($arn): ($arn | capture("::(?<a>[0-9]+):") | .a) // "";

def principal_ref($p): { kind: $p.kind, name: $p.name, arn: $p.arn };

def finding($id; $sev; $title; $p; $detail; $fix; $tactic):
  { id: $id, severity: $sev, title: $title, principal: principal_ref($p),
    detail: $detail, fix: $fix, tactic: $tactic };
