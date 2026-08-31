"""Azure privilege escalation checks: the mirror of S7aba's privesc_azure.

The escalation that matters in Azure is control of role assignments. A principal that
can write role assignments can grant itself Owner, and Owner or a wildcard role is
full control. User Access Administrator and elevateAccess reach the same place.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p):
            findings.append(_finding("kz" + str(n), "critical", "Owner or a wildcard role", p,
                f"{_principal_label(p)} holds Owner or a role that allows every action, which is full control of everything in scope.",
                "Replace Owner with a role scoped to the actions this principal needs, and keep Owner to a small, monitored set.",
                "privilege escalation"))
            n += 1
            continue
        if acct.allows(p, "microsoft.authorization/roleassignments/write"):
            findings.append(_finding("kz" + str(n), "high", "Can grant itself any role", p,
                f"{_principal_label(p)} can write role assignments, so it can assign itself Owner and take full control.",
                "Remove Microsoft.Authorization/roleAssignments/write, or limit it to a narrow scope under review.",
                "privilege escalation"))
            n += 1
        if acct.allows(p, "microsoft.authorization/elevateaccess/action"):
            findings.append(_finding("kz" + str(n), "high", "Can elevate to tenant root access", p,
                f"{_principal_label(p)} can call elevateAccess, which grants User Access Administrator at the root of the tenant.",
                "Remove the elevateAccess permission from this principal.",
                "privilege escalation"))
            n += 1
        if acct.allows(p, "microsoft.authorization/roledefinitions/write") and not acct.allows(p, "microsoft.authorization/roleassignments/write"):
            findings.append(_finding("kz" + str(n), "medium", "Can write custom role definitions", p,
                f"{_principal_label(p)} can create or change role definitions. Paired with a way to assign them it becomes escalation.",
                "Limit Microsoft.Authorization/roleDefinitions/write to role administrators.",
                "privilege escalation"))
            n += 1
        if acct.allows(p, "microsoft.compute/virtualmachines/runcommand/action") or acct.allows(p, "microsoft.compute/virtualmachines/extensions/write"):
            findings.append(_finding("kz" + str(n), "high", "Can run code on a VM as its managed identity", p,
                f"{_principal_label(p)} can run a command or install an extension on a virtual machine, executing as the managed identity attached to that VM.",
                "Restrict runCommand and extension writes, and avoid attaching privileged managed identities to general purpose VMs.",
                "privilege escalation"))
            n += 1
        if acct.allows(p, "microsoft.automation/automationaccounts/runbooks/write"):
            findings.append(_finding("kz" + str(n), "high", "Can run an Automation runbook as its managed identity", p,
                f"{_principal_label(p)} can write and run an Automation runbook, which executes as the managed identity of the Automation account.",
                "Restrict runbook writes, and scope the Automation account managed identity to what its runbooks need.",
                "privilege escalation"))
            n += 1
        if acct.allows(p, "microsoft.managedidentity/userassignedidentities/assign/action"):
            findings.append(_finding("kz" + str(n), "high", "Can assign a managed identity to a resource", p,
                f"{_principal_label(p)} can assign a user assigned managed identity to a resource it controls, then run as that identity.",
                "Restrict the assign action on user assigned managed identities to the members that provision them.",
                "privilege escalation"))
            n += 1
    return findings
