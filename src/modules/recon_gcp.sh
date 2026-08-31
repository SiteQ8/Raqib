# recon_gcp: the read that maps the project. Viewer reads every resource; reading the
# IAM policy enumerates every member and the roles they hold. Read only.

analyze_recon_gcp() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_gcp"; custom_map as $c |
    [ principals[] as $p
      | if (is_owner($p) or is_public($p)) then empty
        elif (has_role($p; "roles/viewer") and (has_permission($p; "resourcemanager.projects.setiampolicy"; $c)|not)) then
          finding("rg-view"; "low"; "Viewer over the project"; $p;
            ($p.name + " can read every resource in the project, a full map of what is there.");
            "Grant read access at the narrowest scope rather than project wide Viewer."; "reconnaissance")
        elif has_permission($p; "resourcemanager.projects.getiampolicy"; $c) then
          finding("rg-iam"; "low"; "Can read the project IAM policy"; $p;
            ($p.name + " can read the project IAM policy, every member and the roles they hold, the map an intruder draws before choosing a target.");
            "Limit resourcemanager.projects.getIamPolicy to the members that audit access."; "reconnaissance")
        else empty end
    ]' "$1"
}
