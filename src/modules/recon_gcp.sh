analyze_recon_gcp() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_gcp"; custom_map as $c |
    [ principals[] as $p
      | if (is_owner($p) or is_public($p)) then empty
        elif (has_role($p; "roles/viewer") and (has_permission($p; "resourcemanager.projects.setiampolicy"; $c)|not)) then
          finding("rg0"; "low"; "Viewer over the project"; $p;
            ($p.name + " can read every resource in the project, a full map of what is there.");
            "Grant read access at the narrowest scope rather than project wide Viewer."; "reconnaissance")
        else empty end
    ]' "$1"
}
