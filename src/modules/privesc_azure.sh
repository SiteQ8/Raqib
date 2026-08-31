# privesc_azure: control of role assignments and running as a managed identity.
# Owner or a wildcard role is full control. Writing role assignments grants itself
# Owner; elevateAccess reaches tenant root; writing role definitions is escalation
# once a role can be assigned. Running code on a VM, in an Automation runbook, or
# assigning a managed identity all borrow that identity. Read only.

analyze_privesc_azure() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_azure";
    [ principals[] as $p
      | if is_owner($p) then
          finding("kz-own"; "critical"; "Owner or a wildcard role"; $p;
            ($p.name + " holds Owner or a role that allows every action, full control of everything in scope.");
            "Replace Owner with a role scoped to what this principal needs."; "privilege escalation")
        else
          ( if allows($p; "microsoft.authorization/roleassignments/write") then
              finding("kz-grant"; "high"; "Can grant itself any role"; $p;
                ($p.name + " can write role assignments, so it can assign itself Owner.");
                "Remove Microsoft.Authorization/roleAssignments/write or limit it to a narrow scope under review."; "privilege escalation")
            else empty end ),
          ( if allows($p; "microsoft.authorization/elevateaccess/action") then
              finding("kz-elev"; "high"; "Can elevate to tenant root access"; $p;
                ($p.name + " can call elevateAccess, which grants User Access Administrator at the tenant root.");
                "Remove the elevateAccess permission from this principal."; "privilege escalation")
            else empty end ),
          ( if (allows($p; "microsoft.authorization/roledefinitions/write") and (allows($p; "microsoft.authorization/roleassignments/write") | not)) then
              finding("kz-roledef"; "medium"; "Can write custom role definitions"; $p;
                ($p.name + " can create or change role definitions. Paired with a way to assign them it becomes escalation.");
                "Limit Microsoft.Authorization/roleDefinitions/write to role administrators."; "privilege escalation")
            else empty end ),
          ( if (allows($p; "microsoft.compute/virtualmachines/runcommand/action") or allows($p; "microsoft.compute/virtualmachines/extensions/write")) then
              finding("kz-vmmi"; "high"; "Can run code on a VM as its managed identity"; $p;
                ($p.name + " can run a command or install an extension on a virtual machine, executing as the managed identity attached to that VM.");
                "Restrict runCommand and extension writes, and avoid attaching privileged managed identities to general purpose VMs."; "privilege escalation")
            else empty end ),
          ( if allows($p; "microsoft.automation/automationaccounts/runbooks/write") then
              finding("kz-auto"; "high"; "Can run an Automation runbook as its managed identity"; $p;
                ($p.name + " can write and run an Automation runbook, which executes as the managed identity of the Automation account.");
                "Restrict runbook writes, and scope the Automation account managed identity to what its runbooks need."; "privilege escalation")
            else empty end ),
          ( if allows($p; "microsoft.managedidentity/userassignedidentities/assign/action") then
              finding("kz-idassign"; "high"; "Can assign a managed identity to a resource"; $p;
                ($p.name + " can assign a user assigned managed identity to a resource it controls, then run as that identity.");
                "Restrict the assign action on user assigned managed identities to the members that provision them."; "privilege escalation")
            else empty end )
        end
    ]' "$1"
}
