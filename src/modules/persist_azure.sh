# persist_azure: a foothold that outlives the first account. A standing role
# assignment or a new managed identity is durable. A federated identity credential on
# a managed identity lets an external OIDC issuer authenticate as it, a modern back
# door. An Automation account is a durable, scheduled execution surface. Read only.

analyze_persist_azure() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_azure";
    [ principals[] as $p
      | if is_owner($p) then empty
        else
          ( if allows($p; "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials/write") then
              finding("pz-fed"; "high"; "Can add a federated credential to a managed identity"; $p;
                ($p.name + " can add a federated identity credential to a user assigned managed identity, letting an external OIDC issuer authenticate as that identity with no secret to rotate.");
                "Restrict federatedIdentityCredentials writes, and review the trust of every federated credential."; "persistence")
            else empty end ),
          ( if allows($p; "microsoft.managedidentity/userassignedidentities/write") then
              finding("pz-mi"; "medium"; "Can create managed identities"; $p;
                ($p.name + " can create user assigned managed identities, a durable identity an intruder can attach to compute.");
                "Limit creation of managed identities to the principals that provision them."; "persistence")
            else empty end ),
          ( if allows($p; "microsoft.automation/automationaccounts/write") then
              finding("pz-auto"; "medium"; "Can create an Automation account"; $p;
                ($p.name + " can create an Automation account, a durable and scheduled execution surface that can run as a managed identity.");
                "Limit who can create Automation accounts, and review their runbooks and identities."; "persistence")
            else empty end ),
          ( if allows($p; "microsoft.authorization/roleassignments/write") then
              finding("pz-ra"; "medium"; "Can plant a standing role assignment"; $p;
                ($p.name + " can create role assignments, granting a principal it controls lasting access.");
                "Alert on new role assignments and keep this permission narrow."; "persistence")
            else empty end )
        end
    ]' "$1"
}
