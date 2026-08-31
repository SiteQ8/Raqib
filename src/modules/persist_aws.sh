# persist_aws: creating a new identity and granting it access.
analyze_persist_aws() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_aws";
    [ principals[] as $p
      | if (is_admin($p) or allows($p.stmts; "iam:*"; true)) then empty
        else
          ( (allows($p.stmts; "iam:createuser")) as $mkuser
            | (allows($p.stmts; "iam:createaccesskey") or allows($p.stmts; "iam:attachuserpolicy") or allows($p.stmts; "iam:putuserpolicy")) as $grant
            | if ($mkuser and $grant) then
                finding("p0"; "high"; "Can plant a back door user"; $p;
                  ($p.name + " can create a new IAM user and give it credentials or permissions, a durable foothold left behind.");
                  "Remove the ability to create users, or gate it behind review, and alert on new user creation."; "persistence")
              elif $mkuser then
                finding("p1"; "medium"; "Can create IAM users"; $p;
                  ($p.name + " can create IAM users. Paired with a way to grant access it becomes a back door.");
                  "Limit iam:CreateUser to the principals that provision identities."; "persistence")
              else empty end )
          ,
          ( if (allows($p.stmts; "iam:createrole") and (allows($p.stmts; "iam:attachrolepolicy") or allows($p.stmts; "iam:putrolepolicy"))) then
              finding("p2"; "medium"; "Can create a role and grant it permissions"; $p;
                ($p.name + " can create a new role and attach permissions, which an intruder can use to stand up a role they control.");
                "Limit role creation, and require new roles carry a permissions boundary."; "persistence")
            else empty end )
        end
    ]' "$1"
}
