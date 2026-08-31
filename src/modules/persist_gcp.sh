# persist_gcp: a durable foothold in GCP. A service account key is a long lived
# credential; a fresh service account is a new identity. Setting the IAM policy on a
# service account binds a controlled principal to it as a stealthy back door, and a
# scheduled job re-establishes access on a timer. Read only.

analyze_persist_gcp() {
  jq -L "$RAQIB_ROOT/src/lib" -c 'include "model_gcp"; custom_map as $c |
    [ principals[] as $p
      | if (is_owner($p) or is_public($p)) then empty
        else
          ( if has_permission($p; "iam.serviceaccountkeys.create"; $c) then
              finding("pg-key"; "high"; "Can create service account keys"; $p;
                ($p.name + " can create keys for service accounts, a long lived credential an intruder can keep using.");
                "Remove roles/iam.serviceAccountKeyAdmin, and prefer short lived credentials."; "persistence")
            elif has_permission($p; "iam.serviceaccounts.create"; $c) then
              finding("pg-sa"; "medium"; "Can create service accounts"; $p;
                ($p.name + " can create service accounts, a fresh identity an intruder can stand up.");
                "Limit roles/iam.serviceAccountAdmin to the members that provision identities."; "persistence")
            else empty end ),
          ( if has_permission($p; "iam.serviceaccounts.setiampolicy"; $c) then
              finding("pg-sapol"; "medium"; "Can grant lasting access to a service account"; $p;
                ($p.name + " can set the IAM policy on a service account, binding a principal it controls as a token creator, a stealthy back door into that identity.");
                "Restrict iam.serviceAccounts.setIamPolicy, and review who is bound on high value service accounts."; "persistence")
            else empty end ),
          ( if has_permission($p; "cloudscheduler.jobs.create"; $c) then
              finding("pg-sched"; "medium"; "Can plant a scheduled job"; $p;
                ($p.name + " can create Cloud Scheduler jobs, a timer an intruder can use to trigger a callback again and return.");
                "Limit cloudscheduler.jobs.create, and review scheduled jobs for unexpected targets."; "persistence")
            else empty end )
        end
    ]' "$1"
}
