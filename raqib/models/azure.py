"""Read an Azure authorization export into principals Raqib can reason about.

Azure controls access with role assignments and role definitions. A role definition
lists the actions it allows and the ones it takes back, across control plane actions
and data plane dataActions. A role assignment binds a principal, a user, group, or
service principal, to a role at a scope. This module resolves each principal to the
set of actions it effectively holds and the broadest scope it holds them at.

Build the export with the Azure CLI and combine the two lists into one object:

    {
      "roleAssignments": <az role assignment list --all -o json>,
      "roleDefinitions": <az role definition list -o json>
    }

Everything here is read only. Raqib never calls Azure.
"""


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _match(pattern, action):
    pattern = pattern.lower()
    action = action.lower()
    if pattern == "*":
        return True
    if "*" not in pattern:
        return pattern == action
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


# how broad a scope is, larger means more of the tenant
def _scope_rank(scope):
    s = (scope or "").lower()
    if s in ("/", ""):
        return 5
    if s.startswith("/providers/microsoft.management/managementgroups"):
        return 4
    if "/resourcegroups/" in s:
        return 2
    if s.count("/") <= 2 and s.startswith("/subscriptions/"):
        return 3  # subscription scope
    return 1  # a single resource


class Principal:
    def __init__(self, pid, kind, name):
        self.id = pid
        self.arn = pid
        self.kind = kind          # User, Group, ServicePrincipal
        self.name = name or pid
        self.assignments = []     # list of (role_name, actions, not_actions, data_actions, scope)

    def _statements(self):
        return self.assignments

    @property
    def broadest_scope_rank(self):
        return max([_scope_rank(a[4]) for a in self.assignments], default=0)


class Account:
    def __init__(self):
        self.principals = []

    def allows(self, principal, action, require_broad=False):
        """Does the principal hold a control plane action, after notActions remove it."""
        action = action.lower()
        for role_name, actions, not_actions, data_actions, scope in principal.assignments:
            if require_broad and _scope_rank(scope) < 3:
                continue
            if any(_match(p, action) for p in not_actions):
                continue
            if any(_match(p, action) for p in actions):
                return True
        return False

    def allows_data(self, principal, action):
        action = action.lower()
        for role_name, actions, not_actions, data_actions, scope in principal.assignments:
            if any(_match(p, action) for p in data_actions):
                return True
        return False

    def has_role(self, principal, role_name):
        return any(r[0].lower() == role_name.lower() for r in principal.assignments)

    def is_owner(self, principal):
        # Owner is action * without the notActions that Contributor carries
        for role_name, actions, not_actions, data_actions, scope in principal.assignments:
            if role_name.lower() == "owner":
                return True
            if any(a == "*" for a in actions) and not any("authorization" in n.lower() for n in not_actions):
                return True
        return False


def _role_defs(raw):
    defs = {}
    for rd in _as_list(raw.get("roleDefinitions")):
        props = rd.get("properties", rd)
        name = props.get("roleName") or rd.get("roleName") or rd.get("name", "")
        rid = rd.get("id") or rd.get("name", "")
        actions, not_actions, data_actions = [], [], []
        for perm in _as_list(props.get("permissions")):
            actions += [a.lower() for a in _as_list(perm.get("actions"))]
            not_actions += [a.lower() for a in _as_list(perm.get("notActions"))]
            data_actions += [a.lower() for a in _as_list(perm.get("dataActions"))]
        entry = {"name": name, "actions": actions, "not_actions": not_actions, "data_actions": data_actions}
        if rid:
            defs[rid.lower()] = entry
        defs[("name:" + name).lower()] = entry
    return defs


def load(raw):
    acct = Account()
    defs = _role_defs(raw)
    principals = {}

    for ra in _as_list(raw.get("roleAssignments")):
        props = ra.get("properties", ra)
        pid = props.get("principalId") or ra.get("principalId", "")
        ptype = props.get("principalType") or ra.get("principalType", "Unknown")
        pname = props.get("principalName") or props.get("principalDisplayName") or pid
        scope = props.get("scope") or ra.get("scope", "")
        rdid = props.get("roleDefinitionId") or ra.get("roleDefinitionId", "")
        role_name = props.get("roleName") or ""

        entry = defs.get((rdid or "").lower())
        if entry is None and role_name:
            entry = defs.get(("name:" + role_name).lower())
        if entry is None:
            # a well known role we did not get a definition for; key on its name
            entry = {"name": role_name or _builtin_name(rdid), "actions": _builtin_actions(role_name or _builtin_name(rdid)),
                     "not_actions": [], "data_actions": []}

        if pid not in principals:
            principals[pid] = Principal(pid, ptype, pname)
        principals[pid].assignments.append(
            (entry["name"], entry["actions"], entry["not_actions"], entry["data_actions"], scope))

    acct.principals = list(principals.values())
    return acct


# a few built in roles by their well known id, so an export of assignments alone
# still resolves the ones that matter most
_BUILTIN_IDS = {
    "8e3af657a8ff443ca75c2fe8c4bcb635": "Owner",
    "b24988ac6180": "Contributor",
    "acdd72a7f321": "Reader",
    "18d7d88d9b1f": "User Access Administrator",
}


def _builtin_name(rdid):
    low = (rdid or "").lower()
    for frag, name in _BUILTIN_IDS.items():
        if frag in low:
            return name
    return rdid or "Unknown"


def _builtin_actions(name):
    n = (name or "").lower()
    if n == "owner":
        return ["*"]
    if n == "contributor":
        return ["*"]  # Contributor is * with notActions on authorization, handled by is_owner
    if n == "user access administrator":
        return ["*/read", "microsoft.authorization/*"]
    if n == "reader":
        return ["*/read"]
    return []


def load_file(path):
    import json
    with open(path, "r", encoding="utf-8") as fh:
        return load(json.load(fh))
