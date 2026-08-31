"""The rules Raqib runs against a resolved account.

Each rule looks for a way a principal could gain more than it was meant to have,
the way an attacker who already holds that principal's credentials would. The
privilege escalation paths are the well known IAM primitives: rewriting a policy
you are attached to, attaching an administrator policy, setting a login password
on another user, passing a powerful role to a compute service you can start, and
so on. Raqib reports each with the move it enables and the change that closes it.

The severities read as: critical is administrator equivalent or assumable by
anyone, high is a direct escalation to administrator, medium is a path that needs
another condition to be met or is limited by a resource restriction to verify, and
low is hygiene that an attacker would still be glad to find.

Nothing here executes anything. A finding describes what the permission would
allow, not proof that it was used.
"""

# Each escalation method: the actions it needs, a title, the move it enables, and
# the fix. When every action is present, the path is open.
PRIVESC_METHODS = [
    {
        "id": "policy-version",
        "actions": ["iam:createpolicyversion"],
        "title": "Can rewrite an attached policy",
        "enables": "Create a new default version of a customer managed policy the principal is attached to and write administrator permissions into it.",
        "fix": "Remove iam:CreatePolicyVersion, or scope it to policies that grant no access this principal lacks.",
    },
    {
        "id": "set-default-version",
        "actions": ["iam:setdefaultpolicyversion"],
        "title": "Can roll a policy back to a more permissive version",
        "enables": "Set an older, more permissive version of an attached policy as the default.",
        "fix": "Remove iam:SetDefaultPolicyVersion unless it is scoped to policies that cannot raise this principal's access.",
    },
    {
        "id": "attach-user-policy",
        "actions": ["iam:attachuserpolicy"],
        "title": "Can attach any managed policy to a user",
        "enables": "Attach AdministratorAccess to itself or another user.",
        "fix": "Remove iam:AttachUserPolicy, or add a permissions boundary and a condition that limits which policies may be attached.",
    },
    {
        "id": "attach-group-policy",
        "actions": ["iam:attachgrouppolicy"],
        "title": "Can attach any managed policy to a group",
        "enables": "Attach AdministratorAccess to a group the principal belongs to.",
        "fix": "Remove iam:AttachGroupPolicy, or restrict which policies may be attached.",
    },
    {
        "id": "attach-role-policy",
        "actions": ["iam:attachrolepolicy"],
        "title": "Can attach any managed policy to a role",
        "enables": "Attach AdministratorAccess to a role the principal can assume or use.",
        "fix": "Remove iam:AttachRolePolicy, or restrict which policies may be attached.",
    },
    {
        "id": "put-user-policy",
        "actions": ["iam:putuserpolicy"],
        "title": "Can write an inline policy onto a user",
        "enables": "Write an inline policy granting itself full administrator permissions.",
        "fix": "Remove iam:PutUserPolicy, or add a permissions boundary that caps the effective grant.",
    },
    {
        "id": "put-group-policy",
        "actions": ["iam:putgrouppolicy"],
        "title": "Can write an inline policy onto a group",
        "enables": "Write an inline administrator policy onto a group the principal belongs to.",
        "fix": "Remove iam:PutGroupPolicy, or restrict its use.",
    },
    {
        "id": "put-role-policy",
        "actions": ["iam:putrolepolicy"],
        "title": "Can write an inline policy onto a role",
        "enables": "Write an inline administrator policy onto a role the principal can assume.",
        "fix": "Remove iam:PutRolePolicy, or add a permissions boundary on the target roles.",
    },
    {
        "id": "create-access-key",
        "actions": ["iam:createaccesskey"],
        "title": "Can mint access keys for another user",
        "enables": "Create a second set of access keys for a more privileged user and act as them.",
        "fix": "Scope iam:CreateAccessKey to the principal's own user with a condition on the resource.",
    },
    {
        "id": "create-login-profile",
        "actions": ["iam:createloginprofile"],
        "title": "Can set a console password on a user with none",
        "enables": "Set a console password on a privileged user that has no console access yet, then sign in as them.",
        "fix": "Scope iam:CreateLoginProfile to the principal's own user.",
    },
    {
        "id": "update-login-profile",
        "actions": ["iam:updateloginprofile"],
        "title": "Can reset another user's console password",
        "enables": "Reset the console password of a more privileged user and sign in as them.",
        "fix": "Scope iam:UpdateLoginProfile to the principal's own user.",
    },
    {
        "id": "add-user-to-group",
        "actions": ["iam:addusertogroup"],
        "title": "Can add itself to any group",
        "enables": "Add itself to an administrator group.",
        "fix": "Remove iam:AddUserToGroup, or restrict which groups may be joined.",
    },
    {
        "id": "update-assume-role-policy",
        "actions": ["iam:updateassumerolepolicy", "sts:assumerole"],
        "title": "Can rewrite a role's trust policy and assume it",
        "enables": "Rewrite a privileged role's trust policy to trust itself, then assume the role.",
        "fix": "Remove iam:UpdateAssumeRolePolicy, or scope it away from roles more privileged than this principal.",
    },
    {
        "id": "passrole-ec2",
        "actions": ["iam:passrole", "ec2:runinstances"],
        "title": "Can pass a role to a new EC2 instance",
        "enables": "Launch an instance with a powerful instance profile and use its credentials.",
        "fix": "Scope iam:PassRole to specific low privilege roles, and restrict ec2:RunInstances.",
    },
    {
        "id": "passrole-lambda",
        "actions": ["iam:passrole", "lambda:createfunction", "lambda:invokefunction"],
        "title": "Can pass a role to a new Lambda function and run it",
        "enables": "Create a function with a powerful execution role and invoke it to act as that role.",
        "fix": "Scope iam:PassRole to specific execution roles, and separate function creation from function invocation.",
    },
    {
        "id": "passrole-lambda-eventsource",
        "actions": ["iam:passrole", "lambda:createfunction", "lambda:createeventsourcemapping"],
        "title": "Can pass a role to a Lambda triggered by an event source",
        "enables": "Create a function with a powerful role and trigger it through an event source mapping.",
        "fix": "Scope iam:PassRole to specific execution roles.",
    },
    {
        "id": "passrole-glue",
        "actions": ["iam:passrole", "glue:createdevendpoint"],
        "title": "Can pass a role to a Glue development endpoint",
        "enables": "Create a development endpoint with a powerful role and reach its credentials.",
        "fix": "Scope iam:PassRole to specific Glue roles.",
    },
    {
        "id": "passrole-cloudformation",
        "actions": ["iam:passrole", "cloudformation:createstack"],
        "title": "Can pass a role to a CloudFormation stack",
        "enables": "Create a stack that runs with a powerful role and provisions resources as it.",
        "fix": "Scope iam:PassRole to specific deployment roles, and restrict who may create stacks.",
    },
    {
        "id": "passrole-datapipeline",
        "actions": ["iam:passrole", "datapipeline:createpipeline", "datapipeline:putpipelinedefinition"],
        "title": "Can pass a role to a Data Pipeline",
        "enables": "Create and define a pipeline that runs with a powerful role.",
        "fix": "Scope iam:PassRole to specific pipeline roles.",
    },
    {
        "id": "passrole-sagemaker",
        "actions": ["iam:passrole", "sagemaker:createnotebookinstance"],
        "title": "Can pass a role to a SageMaker notebook",
        "enables": "Create a notebook instance with a powerful role and use its credentials.",
        "fix": "Scope iam:PassRole to specific SageMaker roles.",
    },
    {
        "id": "passrole-codebuild",
        "actions": ["iam:passrole", "codebuild:createproject", "codebuild:startbuild"],
        "title": "Can pass a role to a CodeBuild project",
        "enables": "Create a build project with a powerful service role and start a build that acts as it.",
        "fix": "Scope iam:PassRole to specific CodeBuild roles.",
    },
]

STAR = "\u2605"


def _finding(fid, severity, title, principal, detail, fix, tactic, refs=None):
    return {
        "id": fid,
        "severity": severity,
        "title": title,
        "principal": {"kind": principal.kind, "name": principal.name, "arn": principal.arn} if principal else None,
        "detail": detail,
        "fix": fix,
        "tactic": tactic,
        "refs": refs or [],
    }


def _principal_label(p):
    return (p.kind + " " + p.name) if p else "the account"


def _account_id(arn):
    parts = str(arn).split(":")
    return parts[4] if len(parts) > 4 and parts[4].isdigit() else None


def _wild_services(acct, p):
    """Services this principal holds a full wildcard over, on resource *."""
    out = set()
    for s in p.allow_statements():
        if not s.resource_is_star or s.has_condition or s.not_actions:
            continue
        for a in s.actions:
            if a == "*":
                out.add("*")
            elif a.endswith(":*"):
                out.add(a.split(":", 1)[0])
    return out


def check_privilege_escalation(acct):
    findings = []
    n = 0
    for p in acct.principals:
        admin = acct.admin_statement(p)
        if admin or p.attached_admin:
            title = "Administrator by attached policy" if p.attached_admin else "Administrator by wildcard permission"
            if p.attached_admin:
                detail = f"{_principal_label(p)} has {', '.join(sorted(set(p.attached_admin)))} attached, which grants full control of the account."
            else:
                verb = "an Allow on NotAction with resource *" if any(s.not_actions for s in [admin]) else "an Allow on action * with resource *"
                detail = f"{_principal_label(p)} has {verb}, which is equivalent to AdministratorAccess."
            findings.append(_finding(
                "k" + str(n), "critical", title, p, detail,
                "Replace the blanket grant with only the actions this principal needs. Keep administrator access to a small, monitored set of principals.",
                "privilege escalation",
            ))
            n += 1
            continue  # every narrower path below is subsumed by full admin

        wild = _wild_services(acct, p)
        for method in PRIVESC_METHODS:
            services = {a.split(":", 1)[0] for a in method["actions"]}
            if services and services.issubset(wild):
                continue  # a service wildcard already covers this path and is reported on its own
            if not acct.has_all(p, method["actions"], require_unscoped=True):
                # not open unconditionally on resource *; see if a scoped grant exists
                if acct.has_all(p, method["actions"]):
                    findings.append(_finding(
                        "k" + str(n), "medium", method["title"] + ", possibly limited by a resource restriction", p,
                        f"{_principal_label(p)} can {method['enables'][0].lower() + method['enables'][1:]} The grant is scoped to specific resources, so confirm the scope does not include a target more privileged than this principal.",
                        method["fix"], "privilege escalation",
                        refs=["escalation path: " + method["id"]],
                    ))
                    n += 1
                continue
            findings.append(_finding(
                "k" + str(n), "high", method["title"], p,
                f"{_principal_label(p)} can {method['enables'][0].lower() + method['enables'][1:]}",
                method["fix"], "privilege escalation",
                refs=["escalation path: " + method["id"]],
            ))
            n += 1
    return findings


def check_trust(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if p.kind != "role" or not p.trust:
            continue
        for stmt in _as_list(p.trust.get("Statement")):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            has_condition = bool(stmt.get("Condition"))
            aws = principal.get("AWS") if isinstance(principal, dict) else None
            aws_list = aws if isinstance(aws, list) else ([aws] if aws else [])
            if principal == "*" or "*" in aws_list:
                findings.append(_finding(
                    "t" + str(n), "critical", "Role can be assumed by anyone",
                    p, f"The trust policy of role {p.name} allows any principal to assume it" + (", though a condition is present, so verify the condition truly restricts who can assume it." if has_condition else ", with no condition to restrict it. Any AWS account can take on this role."),
                    "Restrict the trust policy to the specific accounts, roles, or services that should assume this role.",
                    "lateral movement",
                ))
                n += 1
                continue
            own_account = _account_id(p.arn)
            for arn in aws_list:
                if not isinstance(arn, str):
                    continue
                other = _account_id(arn)
                if not arn.startswith("arn:aws:iam::") or other is None or other == own_account:
                    continue
                if ":root" in arn or "/" in arn:
                    findings.append(_finding(
                        "t" + str(n), "medium", "Role trusts an external account",
                        p, f"The trust policy of role {p.name} allows {arn} to assume it. If that account is a third party, a missing external id lets a confused deputy assume the role on a caller's behalf." if not has_condition else f"The trust policy of role {p.name} allows {arn} to assume it under a condition. Confirm the account is yours or a trusted partner.",
                        "Confirm the account is one you control or a trusted partner, and require an external id condition for third party access.",
                        "lateral movement",
                    ))
                    n += 1
            federated = principal.get("Federated") if isinstance(principal, dict) else None
            if federated and not has_condition:
                findings.append(_finding(
                    "t" + str(n), "medium", "Federated trust without a condition",
                    p, f"Role {p.name} trusts a federated identity provider with no condition, so any identity from that provider can assume it.",
                    "Add a condition that limits which federated subjects or audiences may assume the role.",
                    "lateral movement",
                ))
                n += 1
    return findings


def check_wildcards(acct):
    findings = []
    n = 0
    SENSITIVE_SERVICES = {"iam", "sts", "kms", "s3", "secretsmanager", "ec2", "lambda"}
    for p in acct.principals:
        if acct.admin_statement(p):
            continue  # already reported as administrator
        seen = set()
        for s in p.allow_statements():
            for a in s.actions:
                if a.endswith(":*"):
                    svc = a.split(":", 1)[0]
                    if svc in SENSITIVE_SERVICES and svc not in seen:
                        seen.add(svc)
                        findings.append(_finding(
                            "w" + str(n), "medium" if svc not in ("iam", "sts") else "high",
                            f"Full control of {svc} through a service wildcard",
                            p, f"{_principal_label(p)} is allowed {svc}:* , every action in a sensitive service" + (" on resource *." if s.resource_is_star else "."),
                            f"List only the {svc} actions this principal uses instead of the {svc}:* wildcard.",
                            "privilege escalation" if svc in ("iam", "sts") else "reconnaissance",
                        ))
                        n += 1
    return findings


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def run(acct):
    """Run every rule and return the findings, ordered by severity."""
    findings = []
    findings += check_privilege_escalation(acct)
    findings += check_trust(acct)
    findings += check_wildcards(acct)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return findings


def summarize(findings, acct):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    principals_with = len({f["principal"]["arn"] for f in findings if f["principal"]})
    return {
        "counts": counts,
        "total": len(findings),
        "principals": len(acct.principals),
        "principals_with_findings": principals_with,
    }
