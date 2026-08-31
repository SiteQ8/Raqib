"""Read a GCP IAM policy export into principals Raqib can reason about.

GCP grants access by binding a role to a set of members on a resource. The export is
what `gcloud projects get-iam-policy PROJECT --format=json` produces, an object with
bindings, each a role and its members. Custom roles, when included, carry their own
list of permissions.

    {
      "bindings": [ {"role": "roles/owner", "members": ["user:a@x.com"]}, ... ],
      "customRoles": [ {"name": "projects/p/roles/deployer", "includedPermissions": [...]} ]
    }

This module resolves each member to the roles bound to it. Predefined roles are known
by name; custom roles are read from their permissions. Read only, never calls GCP.
"""


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _kind(member):
    prefix = member.split(":", 1)[0] if ":" in member else member
    return {"user": "user", "serviceAccount": "service account", "group": "group",
            "domain": "domain", "allUsers": "public", "allAuthenticatedUsers": "public"}.get(prefix, prefix)


class Principal:
    def __init__(self, member):
        self.member = member
        self.arn = member
        self.kind = _kind(member)
        self.name = member.split(":", 1)[1] if ":" in member else member
        self.roles = set()

    @property
    def is_public(self):
        return self.member in ("allUsers", "allAuthenticatedUsers")


# predefined roles that carry a capability Raqib cares about, and the permissions the
# capability rests on, so custom roles are caught too
ROLE_PERMISSIONS = {
    "roles/owner": {"resourcemanager.projects.setiampolicy", "iam.serviceaccounts.actas", "*"},
    "roles/editor": {"iam.serviceaccounts.actas"},
    "roles/iam.securityadmin": {"resourcemanager.projects.setiampolicy"},
    "roles/resourcemanager.projectiamadmin": {"resourcemanager.projects.setiampolicy"},
    "roles/iam.serviceaccounttokencreator": {"iam.serviceaccounts.getaccesstoken"},
    "roles/iam.serviceaccountuser": {"iam.serviceaccounts.actas"},
    "roles/iam.serviceaccountkeyadmin": {"iam.serviceaccountkeys.create"},
    "roles/iam.serviceaccountadmin": {"iam.serviceaccounts.create"},
    "roles/storage.objectviewer": {"storage.objects.get"},
    "roles/storage.admin": {"storage.objects.get", "storage.buckets.setiampolicy"},
    "roles/secretmanager.secretaccessor": {"secretmanager.versions.access"},
    "roles/bigquery.dataviewer": {"bigquery.tables.getdata"},
    "roles/logging.admin": {"logging.sinks.delete", "logging.logs.delete"},
    "roles/viewer": {"*read*"},
}


class Account:
    def __init__(self):
        self.principals = []
        self.custom = {}  # role name -> set of permissions

    def _permissions_of(self, role):
        low = role.lower()
        if low in self.custom:
            return self.custom[low]
        return ROLE_PERMISSIONS.get(low, set())

    def has_role(self, principal, role):
        return role.lower() in {r.lower() for r in principal.roles}

    def has_permission(self, principal, permission):
        permission = permission.lower()
        for role in principal.roles:
            perms = self._permissions_of(role)
            if "*" in perms or permission in perms:
                return True
        return False

    def is_owner(self, principal):
        return self.has_role(principal, "roles/owner")


def load(raw):
    acct = Account()
    for cr in _as_list(raw.get("customRoles")):
        name = (cr.get("name") or "").split("/")[-1]
        full = cr.get("name", name)
        perms = {p.lower() for p in _as_list(cr.get("includedPermissions"))}
        acct.custom[full.lower()] = perms
        acct.custom[("roles/" + name).lower()] = perms

    members = {}
    for b in _as_list(raw.get("bindings")):
        role = b.get("role", "")
        for m in _as_list(b.get("members")):
            if m not in members:
                members[m] = Principal(m)
            members[m].roles.add(role)
    acct.principals = list(members.values())
    return acct


def load_file(path):
    import json
    with open(path, "r", encoding="utf-8") as fh:
        return load(json.load(fh))
