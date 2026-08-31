# recon_aws: the call that dumps the whole IAM configuration, and broad enumeration.
analyze_recon_aws() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_aws";
    [ principals[] as $p
      | if (is_admin($p) or allows($p.stmts; "iam:*"; true)) then empty
        elif allows($p.stmts; "iam:getaccountauthorizationdetails") then
          finding("r0"; "medium"; "Can export the entire IAM configuration"; $p;
            ($p.name + " can call iam:GetAccountAuthorizationDetails, which returns every user, role, group, and policy in one response, the first thing an intruder pulls to plan a path.");
            "Limit this action to the principals that audit IAM, and watch for it in the trail."; "reconnaissance")
        elif has_all($p.stmts; ["iam:listusers","iam:listroles","iam:listpolicies"]) then
          finding("r1"; "low"; "Can enumerate identities and policies"; $p;
            ($p.name + " can list the account users, roles, and policies, enough to map who holds what.");
            "Grant IAM read access only where a task needs it."; "reconnaissance")
        else empty end
    ]' "$1"
}
