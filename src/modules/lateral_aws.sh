# lateral_aws: role trust policies that let the wrong caller in.
analyze_lateral_aws() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_aws";
    def princ_strings($t): [ ($t.Statement // [])[] | (.Principal // {}) | (.. | strings) ];
    [ principals[] as $p
      | if ($p.trust == null) then empty
        else
          ( princ_strings($p.trust) ) as $princ
          | account_of($p.arn) as $acct
          | if ($princ | index("*")) != null then
              finding("t0"; "critical"; "Role can be assumed by anyone"; $p;
                ($p.name + " has a trust policy that allows any principal to assume it, so anyone can take this role.");
                "Restrict the trust policy to the specific accounts, roles, or services that should assume this role."; "lateral movement")
            else
              ( [ $princ[] | select(startswith("arn:aws:iam::")) | account_of(.) ]
                | map(select(. != "" and . != $acct)) | unique ) as $ext
              | if (($ext | length) > 0) then
                  finding("t1"; "medium"; "Role trusts an external account"; $p;
                    ($p.name + " trusts a principal in another account (" + ($ext | join(", ")) + "). If that account is compromised, this role is reachable.");
                    "Confirm the external account is meant to assume this role, and add a condition such as an external id."; "lateral movement")
                else empty end
            end
        end
    ]' "$1"
}
