# model_gcp.jq -- resolve a GCP get-iam-policy export (bindings, optional customRoles)
# into members with their roles, and answer role and permission questions. Read only.

def as_array(x): if x == null then [] elif (x|type)=="array" then x else [x] end;

def role_permissions:
  {
    "roles/owner": ["resourcemanager.projects.setiampolicy","iam.serviceaccounts.actas","*"],
    "roles/editor": ["iam.serviceaccounts.actas"],
    "roles/iam.securityadmin": ["resourcemanager.projects.setiampolicy"],
    "roles/resourcemanager.projectiamadmin": ["resourcemanager.projects.setiampolicy"],
    "roles/iam.serviceaccounttokencreator": ["iam.serviceaccounts.getaccesstoken","iam.serviceaccounts.getopenidtoken","iam.serviceaccounts.signblob","iam.serviceaccounts.signjwt"],
    "roles/iam.serviceaccountuser": ["iam.serviceaccounts.actas"],
    "roles/iam.serviceaccountkeyadmin": ["iam.serviceaccountkeys.create"],
    "roles/iam.serviceaccountadmin": ["iam.serviceaccounts.create","iam.serviceaccounts.setiampolicy"],
    "roles/cloudscheduler.admin": ["cloudscheduler.jobs.create"],
    "roles/iam.roleadmin": ["iam.roles.update"],
    "roles/iam.organizationroleadmin": ["iam.roles.update"],
    "roles/cloudfunctions.developer": ["cloudfunctions.functions.create"],
    "roles/compute.instanceadmin.v1": ["compute.instances.create"],
    "roles/run.admin": ["run.services.create"],
    "roles/cloudbuild.builds.editor": ["cloudbuild.builds.create"],
    "roles/deploymentmanager.editor": ["deploymentmanager.deployments.create"],
    "roles/storage.objectviewer": ["storage.objects.get"],
    "roles/storage.admin": ["storage.objects.get","storage.buckets.setiampolicy"],
    "roles/secretmanager.secretaccessor": ["secretmanager.versions.access"],
    "roles/bigquery.dataviewer": ["bigquery.tables.getdata"],
    "roles/logging.admin": ["logging.sinks.delete","logging.logs.delete"],
    "roles/viewer": ["*read*"]
  };

def kind_of($m):
  ($m | split(":")[0]) as $pre
  | {"user":"user","serviceAccount":"service account","group":"group","domain":"domain",
     "allUsers":"public","allAuthenticatedUsers":"public"}[$pre] // $pre;

def custom_map:
  reduce (.customRoles[]?) as $c ({};
    ($c.name // "") as $full
    | ($full | split("/") | last) as $short
    | ([ ($c.includedPermissions // [])[] | ascii_downcase ]) as $perms
    | . + { ($full|ascii_downcase): $perms, (("roles/" + $short)|ascii_downcase): $perms });

def principals:
  ( reduce (.bindings[]?) as $b ({};
      $b.role as $role
      | reduce (as_array($b.members)[]) as $m (.;
          .[$m] += {member:$m, arn:$m, kind:kind_of($m), name:($m | sub("^[^:]*:";"")), roles:[$role]} ) )
    | [ .[] ] )
  | map(. + {roles: (.roles | unique)});

def perms_of($role; $custom):
  ($role|ascii_downcase) as $l
  | ($custom[$l] // role_permissions[$l] // []);

def has_role($p; $role): any($p.roles[]; (.|ascii_downcase) == ($role|ascii_downcase));

def has_permission($p; $perm; $custom):
  ($perm|ascii_downcase) as $x
  | any($p.roles[]; perms_of(.; $custom) as $ps | (($ps|index("*")) != null) or (($ps|index($x)) != null));

def is_owner($p): has_role($p; "roles/owner");
def is_public($p): (.member == "allUsers" or .member == "allAuthenticatedUsers");

def principal_ref($p): { kind: $p.kind, name: $p.name, arn: $p.arn };
def finding($id; $sev; $title; $p; $detail; $fix; $tactic):
  { id:$id, severity:$sev, title:$title, principal:principal_ref($p), detail:$detail, fix:$fix, tactic:$tactic };
