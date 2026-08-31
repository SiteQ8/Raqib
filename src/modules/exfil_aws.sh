# exfil_aws: the permission to read data broadly, or share a snapshot out. This reads
# the permission to exfiltrate, not a resource left public through a resource policy.
analyze_exfil_aws() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_aws";
    def groups: [
      {label:"read every secret in Secrets Manager", a:["secretsmanager:getsecretvalue"], hi:true},
      {label:"read objects in any bucket", a:["s3:getobject"], hi:true},
      {label:"make an EBS snapshot public or share it", a:["ec2:modifysnapshotattribute"], hi:true},
      {label:"share a database snapshot outside the account", a:["rds:modifydbsnapshotattribute","rds:modifydbclustersnapshotattribute"], hi:true},
      {label:"read every SSM parameter", a:["ssm:getparameter","ssm:getparameters","ssm:getparametersbypath"], hi:false},
      {label:"read or export any DynamoDB table", a:["dynamodb:scan","dynamodb:exporttabletopointintime"], hi:false},
      {label:"decrypt data with any KMS key", a:["kms:decrypt"], hi:false}
    ];
    [ principals[] as $p
      | if (is_admin($p)) then empty
        else
          ( [ groups[] as $g
              | ($g.a[0] | split(":")[0]) as $svc
              | if allows($p.stmts; ($svc + ":*"); true) then empty
                elif any($g.a[]; . as $a | allows($p.stmts; $a; true)) then {label:$g.label, hi:$g.hi}
                else empty end ] ) as $caps
          | if (($caps|length) == 0) then empty
            else
              ( if any($caps[]; .hi) then "high" else "medium" end ) as $sev
              | ( [ $caps[].label ] ) as $labels
              | ( if ($labels|length)==1 then $labels[0] else ($labels[:-1]|join(", ")) + ", and " + $labels[-1] end ) as $joined
              | finding("x0"; $sev; "Can read or move data broadly"; $p;
                  ($p.name + " can " + $joined + ". An intruder holding this principal would use it to pull data out.");
                  "Scope these actions to the specific secrets, buckets, parameters, and tables the principal needs."; "exfiltration")
            end
        end
    ]' "$1"
}
