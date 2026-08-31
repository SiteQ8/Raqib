analyze_persist_gcp() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_gcp"; custom_map as $c |
    [ principals[] as $p
      | if (is_owner($p) or is_public($p)) then empty
        elif has_permission($p; "iam.serviceaccountkeys.create"; $c) then
          finding("pg0"; "high"; "Can create service account keys"; $p;
            ($p.name + " can create keys for service accounts, a long lived credential an intruder can keep using.");
            "Remove roles/iam.serviceAccountKeyAdmin, and prefer short lived credentials."; "persistence")
        elif has_permission($p; "iam.serviceaccounts.create"; $c) then
          finding("pg1"; "medium"; "Can create service accounts"; $p;
            ($p.name + " can create service accounts, a fresh identity an intruder can stand up.");
            "Limit roles/iam.serviceAccountAdmin to the members that provision identities."; "persistence")
        else empty end
    ]' "$1"
}
