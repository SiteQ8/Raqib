# Raqib

A read only lookout over your cloud access. Point Raqib at the cloud you are signed in to and it reads your live authorization configuration with read only calls, then reports the moves an intruder would make after a foothold: mapping the account, turning access into more, planting something to keep it, reaching the next principal, pulling the data out, and turning off the logging that would record it. Each finding says why it is exploitable and the change that closes it.

Raqib (راقب, one who watches over) is the defensive mirror of an offensive framework that runs those same six tactics across AWS, Azure, GCP, and Kubernetes. It reads who can do what, and reports it. It never creates, changes, or deletes anything, and it never reads the contents of a secret, an object, or a key.

Live demo and a sample report: https://siteq8.github.io/Raqib/

![A Raqib report listing findings by severity](docs/hero.png)

## Scan your cloud

No file to export and hand over. Sign in to your cloud the way you already do, then run Raqib. It detects which cloud you are in, reads its authorization configuration, and prints the report.

```
git clone https://github.com/SiteQ8/Raqib.git
cd Raqib
./raqib.sh
```

That is the whole thing. Point it at a cloud, read the exposure, change nothing.

```
./raqib.sh                       scan whatever cloud you are signed in to, live
./raqib.sh --cloud aws           scan one named cloud
./raqib.sh scan --strict         exit non zero if a critical or high finding is present
./raqib.sh scan --json           machine readable findings
./raqib.sh defends               print the whole cloud by tactic map of what Raqib checks
```

Live scanning needs `jq` and the CLI for the cloud you are scanning (`aws`, `az`, `gcloud`, or `kubectl`), already signed in. Nothing else.

## Read only, and how Raqib holds to it

Raqib audits. It does not act. Every call it makes is a read: it lists and describes authorization configuration and nothing more. It has no code path that writes, and a guard refuses any command that is not one of the read only calls below, so a wrong turn cannot change a cloud.

| cloud | Raqib reads, read only | Raqib never |
| --- | --- | --- |
| AWS | `iam get-account-authorization-details` | creates, changes, or deletes, or reads a secret value |
| Azure | `role assignment list`, `role definition list` | writes a role assignment or reads a Key Vault secret |
| GCP | `projects get-iam-policy` | sets an IAM policy or reads an object |
| Kubernetes | `get clusterroles,clusterrolebindings,roles,rolebindings` | applies, deletes, or reads a Secret payload |

Exfiltration findings read the permission to move data, by inspecting the authorization configuration. Raqib checks whether a principal is allowed to read every secret; it never calls the API that returns the secret. The check is on the grant, not the data.

## Four clouds, one lookout

Each cloud has its own authorization model, so Raqib reads each one natively and reports the same six tactics in that cloud's own terms.

| | AWS | Azure | GCP | Kubernetes |
| --- | --- | --- | --- | --- |
| model | IAM policies, inline, attached, and group, with permissions boundaries | RBAC role assignments joined to role definitions | IAM policy bindings, predefined and custom roles | Roles and ClusterRoles resolved through their bindings |

Raqib detects the cloud on its own. Pass `--cloud` to name it. Azure, GCP, and Kubernetes reports read the same as the AWS one, in that cloud's language. See `docs/screenshots/report-azure.png`, `docs/screenshots/report-gcp.png`, and `docs/screenshots/report-k8s.png`.

## The six tactics, read for defense

The checks are a cloud by tactic matrix under `src/modules`, named `{tactic}_{cloud}.sh`, the same six tactics the offensive framework runs, so the defense maps onto the offense one for one. Run `./raqib.sh defends` to see the whole map.

- Reconnaissance: the mapping an attacker does first, the call that dumps the whole IAM configuration in AWS, Reader across a management group in Azure, project Viewer in GCP, cluster wide list in Kubernetes.
- Privilege escalation: the known IAM escalation paths and administrator in AWS, Owner and writing role assignments in Azure, Owner and setIamPolicy and service account impersonation in GCP, cluster-admin and the escalate, bind, and impersonate verbs in Kubernetes.
- Persistence: creating an identity and granting it access, creating service account keys, creating cluster role bindings and admission webhooks.
- Lateral movement: trust that lets the wrong caller in, a role granted to everyone, a service principal with broad reach, reading secrets that hold service account tokens.
- Exfiltration: the permission to read secrets, objects, parameters, and keys broadly, listing storage keys, reading config maps and secrets across a cluster.
- Anti forensics: the ability to stop or delete the account's own record keeping, in each cloud's logging.

Every finding carries the MITRE ATT&CK technique it defends against. AWS is the deepest today, with permissions boundary awareness across the escalation paths; the other three cover the primary paths and have room to grow. Exfiltration reads the permission to move data, which is separate from a resource left open to the public through a resource policy, still to come.

## Reviewing a saved export

Live is the point, but sometimes the operator who scans is not the operator who reads the result, and a captured export travels to an air gapped review. Raqib reads one the same way it reads a live cloud.

```
./raqib.sh scan --offline export.json --cloud aws
```

The export is whatever the read only gather command for that cloud returns, for example `aws iam get-account-authorization-details > export.json`. Raqib detects the cloud from the shape of the file if you leave off `--cloud`.

## An offline engine, for a pipeline

Alongside the scanner, the repository carries a zero dependency Python engine that reads the same exports and adds two things a pipeline wants: SARIF output, so findings appear in a repository's security tab, and, for AWS, credential report findings that the authorization details cannot show, such as a console user without multi factor authentication or an old and still active access key. It needs Python 3.8 or newer and nothing else.

```
aws iam get-account-authorization-details > aws.json
python3 raqib.py audit aws.json --credential-report creds.csv --sarif -o raqib.sarif
python3 raqib.py audit aws.json --strict
```

The engine and the scanner report the same finding taxonomy, so a finding reads the same whichever ran it.

## What a finding means, and what it does not

A finding says what a permission would allow, not that it was used. Raqib reads configuration, not activity. It tells you that a principal could rewrite an attached policy, not that anyone did.

A clean report means the export named nothing these rules look for. It does not mean the account is secure. Raqib checks the paths it knows about; it does not prove their absence everywhere, and it does not yet read resource policies, Azure policy, or organization and folder level bindings, which can widen or narrow real access.

## How it works

The scan runs entirely on what Raqib reads back from the cloud. `raqib.sh` detects the cloud, gathers its authorization configuration with read only calls into a temporary directory, and runs the tactic modules over it. The models live in `src/lib` as `model_{cloud}.jq`, one per cloud, and resolve the raw export into principals with their effective permissions: AWS IAM into inline, attached, and group policies with permissions boundaries read; Azure role assignments joined to role definitions across actions and dataActions; GCP bindings resolved to members with predefined and custom roles; Kubernetes roles resolved to subjects through their bindings, cluster wide or namespaced. The checks are the matrix under `src/modules`, `{tactic}_{cloud}.sh`, each testing the resolved permissions for the exposure that lets its tactic work, and separating an unconditional grant from one a scope already contains. Nothing here executes anything against the cloud beyond reading, and the temporary directory is removed when the scan ends.

The Python engine under `raqib/` mirrors the same layout, `raqib/lib`, `raqib/models`, and `raqib/modules`, for the offline and SARIF path.

## License

MIT. See [LICENSE](LICENSE).
