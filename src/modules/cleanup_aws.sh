# cleanup_aws: principals, beyond administrators, that can weaken the account record.
analyze_cleanup_aws() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_aws";
    def tamper: [
      {label:"stop or delete a CloudTrail trail", a:["cloudtrail:stoplogging","cloudtrail:deletetrail","cloudtrail:updatetrail"]},
      {label:"delete or stop AWS Config", a:["config:deleteconfigurationrecorder","config:stopconfigurationrecorder","config:deletedeliverychannel"]},
      {label:"disable GuardDuty", a:["guardduty:deletedetector","guardduty:updatedetector"]},
      {label:"delete log groups", a:["logs:deleteloggroup","logs:deletelogstream"]},
      {label:"disable Security Hub", a:["securityhub:disablesecurityhub"]}
    ];
    [ principals[] as $p
      | if (is_admin($p)) then empty
        else
          ( [ tamper[] as $t | if any($t.a[]; . as $a | allows($p.stmts; $a)) then $t.label else empty end ] ) as $caps
          | if (($caps|length) == 0) then empty
            else
              ( [ $caps[] ] ) as $labels
              | ( if ($labels|length)==1 then $labels[0] else ($labels[:-1]|join(", ")) + ", and " + $labels[-1] end ) as $joined
              | finding("e0"; "high"; "Can weaken the audit trail"; $p;
                  ($p.name + " can " + $joined + ", which is how an intruder erases the record of what they did.");
                  "Remove these permissions, and protect logging with a service control policy so it cannot be turned off in one account."; "defense evasion")
            end
        end
    ]' "$1"
}
