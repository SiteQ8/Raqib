# privesc_gcp: the documented GCP escalation paths, read only.
# Owner and setIamPolicy are direct control of the project. Impersonating or signing
# as a service account, acting as one to deploy and run as it, rewriting a custom role
# granted to the member, and running as a powerful default service account are the
# paths an intruder walks to turn access into more.

analyze_privesc_gcp() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_gcp";
    def imp: ["iam.serviceaccounts.getaccesstoken","iam.serviceaccounts.getopenidtoken","iam.serviceaccounts.signblob","iam.serviceaccounts.signjwt","iam.serviceaccounts.implicitdelegation"];
    def deploys: [
      {perm:"cloudfunctions.functions.create", tgt:"a Cloud Function"},
      {perm:"compute.instances.create", tgt:"a Compute Engine instance"},
      {perm:"run.services.create", tgt:"a Cloud Run service"}
    ];
    custom_map as $c |
    [ principals[] as $p
      | if is_owner($p) then
          finding("kg-own"; "critical"; "Owner of the project"; $p;
            ($p.name + " holds roles/owner, full control of the project including its IAM policy.");
            "Replace Owner with roles scoped to what this member needs."; "privilege escalation")
        elif is_public($p) then empty
        else
          ( if has_permission($p; "resourcemanager.projects.setiampolicy"; $c) then
              finding("kg-iam"; "high"; "Can rewrite the project IAM policy"; $p;
                ($p.name + " can set the project IAM policy, so it can grant itself Owner.");
                "Remove setIamPolicy unless this member administers IAM."; "privilege escalation")
            else empty end ),
          ( if has_permission($p; "iam.roles.update"; $c) then
              finding("kg-role"; "high"; "Can rewrite a custom role it holds"; $p;
                ($p.name + " can update a custom role, so it can add permissions to a role granted to itself.");
                "Remove roles/iam.roleAdmin unless this member curates custom roles, and keep it off members the role is granted to."; "privilege escalation")
            else empty end ),
          ( if any(imp[]; has_permission($p; .; $c)) then
              finding("kg-imp"; "high"; "Can impersonate service accounts"; $p;
                ($p.name + " can mint tokens for or sign as a service account, borrowing the access of a more powerful one.");
                "Remove roles/iam.serviceAccountTokenCreator unless this member must impersonate a specific service account."; "privilege escalation")
            else empty end ),
          ( if has_permission($p; "iam.serviceaccounts.actas"; $c) then
              ( [ deploys[] | select(has_permission($p; .perm; $c)) ] ) as $m
              | if ($m | length) > 0 then
                  ( $m[] | finding("kg-actd"; "high"; ("Can deploy " + .tgt + " as a service account"); $p;
                      ($p.name + " can act as a service account and create " + .tgt + ", which then runs with that account permissions. This is the GCP form of passing a role.");
                      "Separate serviceAccountUser from deploy permissions, and grant it only on the specific service accounts a task needs."; "privilege escalation") )
                else
                  finding("kg-act"; "medium"; "Can act as service accounts"; $p;
                    ($p.name + " can attach a service account to a resource it creates and run as it. Paired with deploy access this becomes escalation.");
                    "Grant roles/iam.serviceAccountUser only on the specific accounts a task needs."; "privilege escalation")
                end
            else empty end ),
          ( if has_permission($p; "cloudbuild.builds.create"; $c) then
              finding("kg-cb"; "high"; "Can run a build as the Cloud Build service account"; $p;
                ($p.name + " can start a Cloud Build build, whose steps run as the Cloud Build service account, an Editor on the project by default.");
                "Restrict cloudbuild.builds.create, and lower the Cloud Build service account from Editor to what builds actually need."; "privilege escalation")
            else empty end ),
          ( if has_permission($p; "deploymentmanager.deployments.create"; $c) then
              finding("kg-dm"; "high"; "Can deploy as the Google APIs service account"; $p;
                ($p.name + " can create a Deployment Manager deployment, which runs as the Google APIs service account, an Editor on the project by default.");
                "Restrict deploymentmanager.deployments.create, and run deployments with a scoped service account."; "privilege escalation")
            else empty end )
        end
    ]' "$1"
}
