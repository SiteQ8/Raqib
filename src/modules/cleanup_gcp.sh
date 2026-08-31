# cleanup_gcp: weakening the record. The record in GCP is Cloud Logging, the sinks that
# route it, and the alerting on top. Deleting sinks or logs, redirecting a sink, or
# deleting alert policies all cut off what would show an intrusion. Read only.

analyze_cleanup_gcp() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_gcp"; custom_map as $c |
    [ principals[] as $p
      | if (is_owner($p) or is_public($p)) then empty
        else
          ( [ (if (has_permission($p; "logging.sinks.delete"; $c) or has_permission($p; "logging.logs.delete"; $c)) then "delete log sinks or logs" else empty end),
              (if has_permission($p; "logging.sinks.update"; $c) then "redirect log routing by updating a sink" else empty end),
              (if has_permission($p; "monitoring.alertpolicies.delete"; $c) then "delete alerting policies so nothing fires" else empty end) ] ) as $caps
          | if (($caps|length)==0) then empty
            else ( if ($caps|length)==1 then $caps[0] else ($caps[:-1]|join(", ")) + ", and " + $caps[-1] end ) as $joined
              | finding("eg0"; "high"; "Can weaken the audit trail"; $p;
                  ($p.name + " can " + $joined + ", how an intruder stops or erases the record of what they did.");
                  "Remove roles/logging.admin and roles/monitoring.admin from principals that do not run them, and route audit logs to a sink another team controls."; "defense evasion")
            end
        end
    ]' "$1"
}
