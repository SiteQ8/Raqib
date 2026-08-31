# lateral_gcp: the bridges an intruder crosses in GCP. A role granted to everyone is
# an open door. A default service account with a broad role is a pivot: compromise the
# compute it is attached to and inherit that reach. A group with a powerful role is an
# opaque grant, its membership is not visible in the IAM policy. Read only.

analyze_lateral_gcp() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_gcp";
    [ principals[] as $p
      | if is_owner($p) then empty
        elif is_public($p) then
          finding("lg-pub"; "critical"; "A role is granted to everyone"; $p;
            ("The project grants roles to " + $p.member + ", which means anyone on the internet, or anyone with a Google account, holds that access.");
            "Remove allUsers and allAuthenticatedUsers from every binding."; "lateral movement")
        else
          ( if (($p.member | test("(-compute@developer\\.gserviceaccount\\.com|@appspot\\.gserviceaccount\\.com|@cloudservices\\.gserviceaccount\\.com)$"))
                and (has_role($p; "roles/editor") or has_role($p; "roles/owner"))) then
              finding("lg-defsa"; "high"; "A default service account holds a broad role"; $p;
                ($p.name + " is a default service account with Editor or Owner. It is attached to compute by default, so a foothold on a VM or a function inherits this reach.");
                "Remove the broad role from the default service account, run workloads as a dedicated least privilege service account, and disable default service account grants."; "lateral movement")
            else empty end ),
          ( if (($p.member | startswith("group:")) and (has_role($p; "roles/owner") or has_role($p; "roles/editor"))) then
              finding("lg-group"; "medium"; "A group holds a powerful role"; $p;
                ($p.name + " is a group granted Owner or Editor. The membership is managed outside the project, so who holds this access is not visible in the IAM policy.");
                "Confirm the group membership is controlled and reviewed, and prefer scoped roles over Owner or Editor on a group."; "lateral movement")
            else empty end )
        end
    ]' "$1"
}
