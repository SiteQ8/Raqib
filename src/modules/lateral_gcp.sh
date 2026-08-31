analyze_lateral_gcp() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_gcp";
    [ principals[] as $p
      | if is_public($p) then
          finding("lg0"; "critical"; "A role is granted to everyone"; $p;
            ("The project grants roles to " + $p.member + ", which means anyone on the internet, or anyone with a Google account, holds that access.");
            "Remove allUsers and allAuthenticatedUsers from every binding."; "lateral movement")
        else empty end
    ]' "$1"
}
