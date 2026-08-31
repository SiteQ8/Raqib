analyze_cleanup_gcp() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_gcp"; custom_map as $c |
    [ principals[] as $p
      | if (is_owner($p) or is_public($p)) then empty
        elif (has_permission($p; "logging.sinks.delete"; $c) or has_permission($p; "logging.logs.delete"; $c)) then
          finding("eg0"; "high"; "Can weaken the audit trail"; $p;
            ($p.name + " can delete log sinks or logs, how an intruder stops or erases the record of what they did.");
            "Remove roles/logging.admin from principals that do not run logging, and route audit logs to a sink another team controls."; "defense evasion")
        else empty end
    ]' "$1"
}
