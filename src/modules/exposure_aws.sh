# exposure_aws: resource policies that open a resource to the public or another
# account. This reads what the IAM export cannot show, an S3 bucket or a KMS key left
# open through its own resource policy. Read only: it inspects the policy, it never
# reads an object or decrypts anything.

analyze_exposure_aws() {
  jq -c '
    def as_array(x): if x == null then [] elif (x|type)=="array" then x else [x] end;
    def principal_strings($s): [ ($s.Principal // {}) | (.. | strings) ];
    def allow_stmts($pol): [ (as_array(($pol // {}).Statement))[] | select((.Effect // "Allow") == "Allow") ];
    def has_condition($s): ($s.Condition != null) and (($s.Condition | length) > 0);
    def action_has($s; $needle):
      any(as_array($s.Action)[]; (ascii_downcase) as $a | ($a == "*" or ($a | test($needle))));
    def efind($id;$sev;$title;$name;$kind;$detail;$fix;$tactic):
      {id:$id, severity:$sev, title:$title, principal:{kind:$kind, name:$name, arn:$name},
       detail:$detail, fix:$fix, tactic:$tactic};
    (.account // "") as $acct
    | (
        # ---- S3 buckets ----
        [ (.buckets // [])[] as $b
          | ($b.name) as $name
          | allow_stmts($b.policy) as $stmts
          | ( [ $stmts[] | select((principal_strings(.) | index("*")) != null) ] ) as $pub
          | ( [ $stmts[] | . as $s
                | (principal_strings($s) | map(select(test("^arn:aws:iam::[0-9]+:"))) | map(capture("::(?<a>[0-9]+):").a))
                | map(select(. != $acct)) | .[] ] | unique ) as $ext
          | ($b.publicAccessBlock) as $pab
          | ( ($pab == null)
              or ($pab.BlockPublicPolicy != true) or ($pab.RestrictPublicBuckets != true)
              or ($pab.BlockPublicAcls != true) or ($pab.IgnorePublicAcls != true) ) as $pab_weak
          | if ( [ $pub[] | select(has_condition(.) | not) ] | length ) > 0 then
              ( if any($pub[]; action_has(.; "getobject") or action_has(.; "s3:\\*")) then "critical" else "high" end ) as $sev
              | efind("xp-s3pub"; $sev; "S3 bucket is open to the public"; $name; "s3 bucket";
                  ($name + " has a bucket policy that allows any principal, so anyone on the internet can reach it. The public access block does not stop a policy like this unless it is fully on.");
                  "Remove the public statement, and turn on all four public access block settings for the bucket or the account."; "public exposure")
            elif (($pub | length) > 0) then
              efind("xp-s3cond"; "medium"; "S3 bucket allows the public under a condition"; $name; "s3 bucket";
                ($name + " allows any principal, restricted by a condition such as a source address. Confirm the condition is the boundary you intend.");
                "Confirm the condition is correct, and prefer a named principal over a public one with a condition."; "public exposure")
            elif (($ext | length) > 0) then
              efind("xp-s3ext"; "high"; "S3 bucket grants another account access"; $name; "s3 bucket";
                ($name + " grants access to another account (" + ($ext | join(", ")) + ") through its bucket policy. If that account is compromised, the bucket is reachable.");
                "Confirm the other account should have this access, and scope the actions and objects it can reach."; "public exposure")
            elif $pab_weak then
              efind("xp-s3pab"; "medium"; "S3 bucket does not fully block public access"; $name; "s3 bucket";
                ($name + " does not have all four public access block settings on, so a future ACL or policy could make it public without warning.");
                "Turn on BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets, ideally at the account level."; "public exposure")
            else empty end ]
        +
        # ---- KMS keys ----
        [ (.kmsKeys // [])[] as $k
          | ($k.keyId) as $name
          | allow_stmts($k.policy) as $stmts
          | ( [ $stmts[] | select((principal_strings(.) | index("*")) != null) ] ) as $pub
          | ( [ $stmts[] | . as $s
                | (principal_strings($s) | map(select(test("^arn:aws:iam::[0-9]+:"))) | map(capture("::(?<a>[0-9]+):").a))
                | map(select(. != $acct)) | .[] ] | unique ) as $ext
          | if ( [ $pub[] | select(has_condition(.) | not) ] | length ) > 0 then
              efind("xp-kmspub"; "high"; "KMS key policy allows any principal"; $name; "kms key";
                ("The key policy for " + $name + " allows any principal to use it, so a leaked key reference could be used to decrypt data.");
                "Restrict the key policy to the specific principals that must use the key."; "public exposure")
            elif (($ext | length) > 0) then
              efind("xp-kmsext"; "medium"; "KMS key policy trusts an external account"; $name; "kms key";
                ("The key policy for " + $name + " grants use to another account (" + ($ext | join(", ")) + ").");
                "Confirm the other account should use this key, and grant only the key actions it needs."; "public exposure")
            else empty end ]
      )
  ' "$1"
}
