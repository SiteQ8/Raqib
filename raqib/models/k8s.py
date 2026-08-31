"""Read a Kubernetes RBAC export into subjects Raqib can reason about.

Kubernetes grants access with Roles and ClusterRoles, each a set of rules over verbs,
apiGroups, and resources, bound to subjects by RoleBindings and ClusterRoleBindings.
The export is a List of those objects, what this produces:

    kubectl get clusterroles,clusterrolebindings,roles,rolebindings -A -o json

This module resolves each subject to the rules bound to it, and notes whether a rule
came from a cluster wide binding or a namespaced one. Read only, never calls a cluster.
"""


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _matches(values, target):
    return "*" in values or target in values


class Rule:
    def __init__(self, raw, cluster_wide):
        self.verbs = [v.lower() for v in _as_list(raw.get("verbs"))]
        self.api_groups = [g.lower() for g in _as_list(raw.get("apiGroups"))]
        self.resources = [r.lower() for r in _as_list(raw.get("resources"))]
        self.resource_names = _as_list(raw.get("resourceNames"))
        self.cluster_wide = cluster_wide

    def grants(self, verb, resource):
        return _matches(self.verbs, verb.lower()) and _matches(self.resources, resource.lower())


class Subject:
    def __init__(self, kind, name, namespace=None):
        self.kind = kind          # User, Group, ServiceAccount
        self.name = name
        self.namespace = namespace
        self.arn = (kind + ":" + (namespace + "/" if namespace else "") + name)
        self.rules = []

    def _label(self):
        return self.name


class Account:
    def __init__(self):
        self.principals = []

    def can(self, subject, verb, resource, cluster_wide_only=False):
        for r in subject.rules:
            if cluster_wide_only and not r.cluster_wide:
                continue
            if r.resource_names:
                continue  # a rule limited to named objects is not the broad grant we flag
            if r.grants(verb, resource):
                return True
        return False

    def is_cluster_admin(self, subject):
        for r in subject.rules:
            if r.cluster_wide and _matches(r.verbs, "*") and _matches(r.resources, "*") and _matches(r.api_groups, "*"):
                return True
        return False


def load(raw):
    acct = Account()
    roles = {}          # (scope, name) -> list of raw rules ; scope is "cluster" or namespace
    bindings = []

    for item in _as_list(raw.get("items")) or [raw]:
        kind = item.get("kind", "")
        meta = item.get("metadata", {})
        name = meta.get("name", "")
        ns = meta.get("namespace")
        if kind == "ClusterRole":
            roles[("cluster", name)] = item.get("rules") or []
        elif kind == "Role":
            roles[(ns or "", name)] = item.get("rules") or []
        elif kind in ("ClusterRoleBinding", "RoleBinding"):
            bindings.append((kind, ns, item.get("roleRef", {}), item.get("subjects") or []))

    subjects = {}

    def _subject(sub):
        kind = sub.get("kind", "")
        name = sub.get("name", "")
        ns = sub.get("namespace")
        key = (kind, name, ns)
        if key not in subjects:
            subjects[key] = Subject(kind, name, ns)
        return subjects[key]

    for kind, ns, ref, subs in bindings:
        ref_kind = ref.get("kind", "")
        ref_name = ref.get("name", "")
        cluster_wide = (kind == "ClusterRoleBinding")
        if ref_kind == "ClusterRole":
            rules = roles.get(("cluster", ref_name), [])
        else:
            rules = roles.get((ns or "", ref_name), [])
        for sub in subs:
            s = _subject(sub)
            for raw_rule in rules:
                s.rules.append(Rule(raw_rule, cluster_wide))

    acct.principals = list(subjects.values())
    return acct


def load_file(path):
    import json
    with open(path, "r", encoding="utf-8") as fh:
        return load(json.load(fh))
