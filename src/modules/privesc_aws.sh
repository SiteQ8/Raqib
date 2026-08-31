# privesc_aws: administrator, the known IAM escalation paths, and service wildcards,
# read with permissions boundary awareness. Read only.

analyze_privesc_aws() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_aws";
    def paths: [
      {t:"Can attach a policy to itself or another user", s:"high", a:["iam:attachuserpolicy"]},
      {t:"Can put an inline policy on a user", s:"high", a:["iam:putuserpolicy"]},
      {t:"Can attach a policy to a role", s:"high", a:["iam:attachrolepolicy"]},
      {t:"Can put an inline policy on a role", s:"high", a:["iam:putrolepolicy"]},
      {t:"Can rewrite an attached policy", s:"high", a:["iam:createpolicyversion"]},
      {t:"Can roll a policy back to a more permissive version", s:"high", a:["iam:setdefaultpolicyversion"]},
      {t:"Can add itself to a group", s:"high", a:["iam:addusertogroup"]},
      {t:"Can rewrite a role trust policy and then assume it", s:"high", a:["iam:updateassumerolepolicy","sts:assumerole"]},
      {t:"Can mint access keys for another user", s:"high", a:["iam:createaccesskey"]},
      {t:"Can reset another user console password", s:"medium", a:["iam:updateloginprofile"]},
      {t:"Can set a console password on a user", s:"medium", a:["iam:createloginprofile"]}
    ];
    def passrole_targets: [
      {svc:"a new EC2 instance", a:"ec2:runinstances"},
      {svc:"a new Lambda function", a:"lambda:createfunction"},
      {svc:"a new Glue development endpoint", a:"glue:createdevendpoint"},
      {svc:"a new CloudFormation stack", a:"cloudformation:createstack"},
      {svc:"a new CodeBuild project", a:"codebuild:createproject"},
      {svc:"a new SageMaker notebook", a:"sagemaker:createnotebookinstance"}
    ];
    # a path is subsumed when every action in it is already covered by a service
    # wildcard the principal holds, so it is reported once as the wildcard, not again.
    def subsumed($p; $actions):
      all($actions[]; . as $a | ($a | split(":")[0]) as $svc | allows($p.stmts; ($svc + ":*"); true));
    [ principals[] as $p
      | (allows($p.stmts; "*"; true)) as $wild
      | if $wild then
          ( if boundary_allows($p; "*") then
              finding("k-adm"; "critical"; "Administrator by wildcard permission"; $p;
                ($p.name + " is allowed every action on every resource, which is full control of the account.");
                "Replace the wildcard with the specific actions this principal needs."; "privilege escalation")
            else
              finding("k-adm"; "high"; "Administrator by wildcard permission"; $p;
                ($p.name + " is allowed every action, though a permissions boundary caps it. If the boundary is ever relaxed this becomes full control.");
                "Replace the wildcard with the specific actions this principal needs, and do not rely on the boundary alone."; "privilege escalation")
            end )
        elif $p.attached_admin then
          finding("k-att"; "critical"; "Administrator by attached policy"; $p;
            ($p.name + " has the AdministratorAccess policy attached, which is full control of the account.");
            "Detach AdministratorAccess and grant a role scoped to what this principal does."; "privilege escalation")
        else
          ( ["iam","sts"][] as $svc
            | if allows($p.stmts; ($svc + ":*"); true) then
                finding("k-wild"; "high"; ("Full control of " + $svc + " through a service wildcard"); $p;
                  ($p.name + " is allowed " + $svc + ":* on every resource, which is control of that whole service.");
                  ("Replace " + $svc + ":* with the specific " + $svc + " actions needed."); "privilege escalation")
              else empty end )
          ,
          ( paths[] as $m
            | if (has_all($p.stmts; $m.a) and (subsumed($p; $m.a) | not)) then
                finding("k-path"; $m.s; $m.t; $p;
                  ($p.name + " holds " + ($m.a|join(", ")) + ", an escalation path.");
                  "Remove or scope these actions so the principal cannot grant itself more."; "privilege escalation")
              else empty end )
          ,
          ( if allows($p.stmts; "iam:passrole") then
              ( passrole_targets[] as $t
                | if allows($p.stmts; $t.a) then
                    finding("k-pass"; "high"; ("Can pass a role to " + $t.svc); $p;
                      ($p.name + " can pass an IAM role and create " + $t.svc + ", running with that role permissions.");
                      "Scope iam:PassRole to specific roles, and separate it from the create permission."; "privilege escalation")
                  else empty end )
            else empty end )
        end
    ]' "$1"
}
