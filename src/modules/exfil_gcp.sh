analyze_exfil_gcp() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_gcp"; custom_map as $c |
    [ principals[] as $p
      | if (is_owner($p) or is_public($p)) then empty
        else
          ( [ (if has_permission($p; "secretmanager.versions.access"; $c) then "read secrets in Secret Manager" else empty end),
              (if has_permission($p; "storage.objects.get"; $c) then "read objects in Cloud Storage" else empty end),
              (if has_permission($p; "bigquery.tables.getdata"; $c) then "read BigQuery table data" else empty end) ] ) as $caps
          | if (($caps|length)==0) then empty
            else ( if ($caps|length)==1 then $caps[0] else ($caps[:-1]|join(", ")) + ", and " + $caps[-1] end ) as $joined
              | ( if any($caps[]; (contains("secret") or contains("Storage"))) then "high" else "medium" end ) as $sev
              | finding("xg0"; $sev; "Can read data broadly"; $p;
                  ($p.name + " can " + $joined + ", across the project rather than a named resource.");
                  "Grant data access on specific buckets, secrets, and datasets, not at the project level."; "exfiltration")
            end
        end
    ]' "$1"
}
