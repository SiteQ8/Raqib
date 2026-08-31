analyze_privesc_gcp() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_gcp"; custom_map as $c |
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
          ( if has_permission($p; "iam.serviceaccounts.getaccesstoken"; $c) then
              finding("kg-imp"; "high"; "Can impersonate service accounts"; $p;
                ($p.name + " can mint access tokens for service accounts, borrowing a more powerful identity.");
                "Remove roles/iam.serviceAccountTokenCreator unless impersonation of a specific account is required."; "privilege escalation")
            elif has_permission($p; "iam.serviceaccounts.actas"; $c) then
              finding("kg-act"; "medium"; "Can act as service accounts"; $p;
                ($p.name + " can attach a service account to a resource it creates and run as it.");
                "Grant roles/iam.serviceAccountUser only on the specific accounts a task needs."; "privilege escalation")
            else empty end )
        end
    ]' "$1"
}
