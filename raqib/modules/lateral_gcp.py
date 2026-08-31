"""GCP lateral movement checks: the mirror of S7aba's lateral_gcp.

Service account impersonation is the bridge in GCP. A member that can mint tokens for
service accounts moves from its own identity to theirs, and onward.
"""

from raqib.lib.common import _finding, _principal_label


def check(acct):
    findings = []
    n = 0
    for p in acct.principals:
        if acct.is_owner(p):
            continue
        # a public member bound to any role is an open door
        if p.is_public:
            findings.append(_finding("lg" + str(n), "critical", "A role is granted to everyone", p,
                f"The project grants roles to {p.member}, which means anyone on the internet, or anyone with a Google account, holds that access.",
                "Remove allUsers and allAuthenticatedUsers from every binding.",
                "lateral movement"))
            n += 1
    return findings
