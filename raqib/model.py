"""Read an AWS IAM authorization details export into a model Raqib can reason about.

The input is the JSON that `aws iam get-account-authorization-details` produces. It
lists every user, group, role, and managed policy in an account, with the policy
documents attached to each. This module turns that into a set of principals, each
carrying the permissions it effectively has once inline policies, attached managed
policies, and group memberships are combined.

Everything here is read only. Raqib never calls AWS and never touches an account.
It reads a file the account owner exported and reasons about it offline.
"""

import json
from urllib.parse import unquote


def _as_document(doc):
    """A policy document may arrive as a decoded object or as a URL encoded string."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        return json.loads(unquote(doc))
    raise ValueError("a policy document was neither an object nor a string")


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class Statement:
    """One statement from a policy, normalized so the rules can read it plainly."""

    def __init__(self, raw, source):
        self.effect = raw.get("Effect", "Deny")
        self.actions = [a.lower() for a in _as_list(raw.get("Action"))]
        self.not_actions = [a.lower() for a in _as_list(raw.get("NotAction"))]
        self.resources = _as_list(raw.get("Resource"))
        self.not_resources = _as_list(raw.get("NotResource"))
        self.condition = raw.get("Condition") or {}
        self.source = source  # a short label saying which policy this came from

    @property
    def allows(self):
        return self.effect == "Allow"

    @property
    def resource_is_star(self):
        return any(r == "*" for r in self.resources)

    @property
    def has_condition(self):
        return bool(self.condition)


class Principal:
    """A user or a role, with its statements gathered from every policy that reaches it."""

    def __init__(self, kind, name, arn):
        self.kind = kind  # "user" or "role"
        self.name = name
        self.arn = arn
        self.statements = []
        self.trust = None            # a role's assume role policy document
        self.attached_admin = []     # names of attached managed policies that grant admin
        self.groups = []             # group names, for users
        self.tags = {}

    def add_document(self, document, source):
        for raw in _as_list(document.get("Statement")):
            self.statements.append(Statement(raw, source))

    def allow_statements(self):
        return [s for s in self.statements if s.allows]


def _match(pattern, action):
    """Match an IAM action against a pattern that may contain the * wildcard."""
    pattern = pattern.lower()
    action = action.lower()
    if pattern == "*":
        return True
    if "*" not in pattern:
        return pattern == action
    # translate the glob into a simple left to right matcher
    parts = pattern.split("*")
    if not action.startswith(parts[0]):
        return False
    pos = len(parts[0])
    for part in parts[1:-1]:
        idx = action.find(part, pos)
        if idx == -1:
            return False
        pos = idx + len(part)
    if parts[-1] and not action.endswith(parts[-1]):
        return False
    return True


class Account:
    """The whole export, resolved into principals with combined permissions."""

    def __init__(self):
        self.principals = []
        self.managed = {}  # policy arn -> {"document":..., "name":..., "admin":bool}

    # permission tests, used by the rules

    def allows(self, principal, action, require_unscoped=False, allow_conditional=True):
        """Does this principal have a statement allowing the action.

        When require_unscoped is set, only a statement whose resource is * counts,
        which is how the rules tell an unconditional grant from one that a resource
        restriction may already contain.
        """
        action = action.lower()
        denied = self._explicitly_denied(principal, action)
        if denied:
            return False
        for s in principal.allow_statements():
            if require_unscoped and not s.resource_is_star:
                continue
            if s.has_condition and not allow_conditional:
                continue
            if self._statement_covers(s, action):
                return True
        return False

    def _statement_covers(self, statement, action):
        if statement.not_actions:
            # an Allow with NotAction grants everything except those, so the action
            # is covered unless it is one of the listed exceptions
            return not any(_match(p, action) for p in statement.not_actions)
        return any(_match(p, action) for p in statement.actions)

    def _explicitly_denied(self, principal, action):
        for s in principal.statements:
            if s.effect != "Deny":
                continue
            if s.not_actions:
                if not any(_match(p, action) for p in s.not_actions):
                    return True
            elif any(_match(p, action) for p in s.actions):
                return True
        return False

    def has_all(self, principal, actions, require_unscoped=False):
        return all(self.allows(principal, a, require_unscoped=require_unscoped) for a in actions)

    def admin_statement(self, principal):
        """Return the statement that makes this principal an administrator, if any."""
        for s in principal.allow_statements():
            if s.resource_is_star and not s.has_condition:
                if not s.not_actions and any(a == "*" for a in s.actions):
                    return s
                if s.not_actions:  # Allow with NotAction and Resource * is nearly admin
                    return s
        return None


ADMIN_POLICY_ARNS = {"arn:aws:iam::aws:policy/AdministratorAccess"}


def load(raw):
    """Build an Account from parsed authorization details JSON."""
    acct = Account()

    # managed policies first, so principals can resolve the ones attached to them
    for pol in raw.get("Policies", []):
        arn = pol.get("Arn", "")
        default = pol.get("DefaultVersionId")
        document = None
        for ver in pol.get("PolicyVersionList", []):
            if ver.get("VersionId") == default or ver.get("IsDefaultVersion"):
                document = _as_document(ver.get("Document", {}))
                break
        admin = arn in ADMIN_POLICY_ARNS
        acct.managed[arn] = {"document": document, "name": pol.get("PolicyName", arn), "admin": admin}

    groups = {}
    for grp in raw.get("GroupDetailList", []):
        groups[grp.get("GroupName")] = grp

    def attach_group(principal, group):
        for inline in group.get("GroupPolicyList", []):
            principal.add_document(_as_document(inline.get("PolicyDocument", {})), "group " + group.get("GroupName", "") + " inline " + inline.get("PolicyName", ""))
        for att in group.get("AttachedManagedPolicies", []):
            _attach_managed(acct, principal, att)

    def _attach_managed(acct, principal, att):
        arn = att.get("PolicyArn", "")
        m = acct.managed.get(arn)
        if m and m.get("document"):
            principal.add_document(m["document"], "managed " + m["name"])
        if (m and m["admin"]) or arn in ADMIN_POLICY_ARNS:
            principal.attached_admin.append(att.get("PolicyName", arn))

    for usr in raw.get("UserDetailList", []):
        p = Principal("user", usr.get("UserName", ""), usr.get("Arn", ""))
        p.tags = {t.get("Key"): t.get("Value") for t in usr.get("Tags", [])}
        for inline in usr.get("UserPolicyList", []):
            p.add_document(_as_document(inline.get("PolicyDocument", {})), "inline " + inline.get("PolicyName", ""))
        for att in usr.get("AttachedManagedPolicies", []):
            _attach_managed(acct, p, att)
        for gname in usr.get("GroupList", []):
            p.groups.append(gname)
            if gname in groups:
                attach_group(p, groups[gname])
        acct.principals.append(p)

    for role in raw.get("RoleDetailList", []):
        p = Principal("role", role.get("RoleName", ""), role.get("Arn", ""))
        p.tags = {t.get("Key"): t.get("Value") for t in role.get("Tags", [])}
        trust = role.get("AssumeRolePolicyDocument")
        if trust is not None:
            p.trust = _as_document(trust)
        for inline in role.get("RolePolicyList", []):
            p.add_document(_as_document(inline.get("PolicyDocument", {})), "inline " + inline.get("PolicyName", ""))
        for att in role.get("AttachedManagedPolicies", []):
            _attach_managed(acct, p, att)
        acct.principals.append(p)

    return acct


def load_file(path):
    with open(path, "r", encoding="utf-8") as fh:
        return load(json.load(fh))
