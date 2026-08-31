"""Tell which cloud an export came from, by the shape of the JSON.

Each cloud produces a different authorization export, so Raqib can usually pick the
right reader on its own. When it cannot, the caller passes the cloud by hand.
"""

CLOUDS = ("aws", "azure", "gcp", "k8s")


def detect_cloud(export):
    if not isinstance(export, dict):
        return None
    keys = set(export.keys())
    if keys & {"UserDetailList", "RoleDetailList", "GroupDetailList", "Policies"}:
        return "aws"
    if keys & {"roleAssignments", "roleDefinitions"}:
        return "azure"
    if "bindings" in keys:
        return "gcp"
    items = export.get("items")
    if isinstance(items, list):
        for it in items:
            if isinstance(it, dict) and it.get("kind") in {"ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding"}:
                return "k8s"
    return None
