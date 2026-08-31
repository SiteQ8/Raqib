# Raqib

A read only lookout over your cloud access. Raqib reads the authorization export your account already produces, for AWS, Azure, GCP, or Kubernetes, and reports the moves an intruder would make after a foothold: mapping the account, turning access into more, planting something to keep it, reaching the next principal, pulling the data out, and turning off the logging that would record it. Each finding says why it is exploitable and the change that closes it.

Raqib (راقب, one who watches over) never calls a cloud and never touches your account. You hand it a file, and it reasons about that file offline.

Live demo and a sample report: https://siteq8.github.io/Raqib/

![A Raqib report listing findings by severity](docs/hero.png)

## Four clouds, one lookout

Raqib is built as the defensive mirror of an offensive framework that runs across AWS, Azure, GCP, and Kubernetes. Each cloud has its own authorization model, so Raqib reads each one natively and reports the same six tactics in that cloud's own terms.

| | AWS | Azure | GCP | Kubernetes |
| --- | --- | --- | --- | --- |
| reads | IAM authorization details | RBAC role assignments and definitions | IAM policy bindings | Roles, ClusterRoles, and their bindings |

Raqib detects which cloud an export is from and reads it. Pass `--cloud` to say so by hand.

Raqib reads each cloud and reports in its own terms:

Azure, GCP, and Kubernetes reports look the same as the AWS one, in that cloud's language. See `docs/report-azure.png`, `docs/report-gcp.png`, and `docs/report-k8s.png`.

## Why it exists

An attacker who lands a single set of credentials does not stop there. They map the account, look for a way to turn that access into more, plant something to keep it, reach the next principal, pull the data out, and turn off the logging that would record any of it. These moves are well known, and every one of them rests on a permission that lives in the authorization configuration, in plain sight, before anyone uses it.

Raqib walks those same paths so you can close them first.

## The six tactics, read for defense

Raqib's checks are organized as a cloud by tactic matrix, the same six tactics an offensive framework runs, in modules named `{tactic}_{cloud}` so the defense maps onto the offense one for one. Run `python3 raqib.py defends` to see the whole map.

- Reconnaissance: the mapping an attacker does first, the call that dumps the whole IAM configuration in AWS, Reader across a management group in Azure, project Viewer in GCP, cluster wide list in Kubernetes.
- Privilege escalation: the known IAM escalation paths and administrator in AWS, Owner and writing role assignments in Azure, Owner and setIamPolicy and service account impersonation in GCP, cluster-admin and the escalate, bind, and impersonate verbs in Kubernetes.
- Persistence: creating an identity and granting it access, creating service account keys, creating cluster role bindings and admission webhooks.
- Lateral movement: trust that lets the wrong caller in, a role granted to everyone, a service principal with broad reach, reading secrets that hold service account tokens.
- Exfiltration: the permission to read secrets, objects, parameters, and keys broadly, listing storage keys, reading config maps and secrets across a cluster.
- Anti forensics: the ability to stop or delete the account's own record keeping, in each cloud's logging.

Every finding carries the MITRE ATT&CK technique it defends against. AWS is the deepest today, with credential report findings and permissions boundary awareness; the other three cover the primary paths and have room to grow. Exfiltration reads the permission to move data, which is separate from a resource left open to the public through a resource policy, still to come.

## Install

Raqib is a single zero dependency Python tool. It needs Python 3.8 or newer and nothing else.

```
git clone https://github.com/SiteQ8/Raqib.git
cd Raqib
python3 raqib.py defends
```

## Use

Produce your cloud's authorization export, then audit it. Raqib detects the cloud.

AWS:

```
aws iam get-account-authorization-details > aws.json
python3 raqib.py audit aws.json
```

Azure, the role assignments and the role definitions, combined into one object:

```
az role assignment list --all -o json > assignments.json
az role definition list -o json > definitions.json
python3 - <<'PY'
import json
json.dump({"roleAssignments": json.load(open("assignments.json")),
           "roleDefinitions": json.load(open("definitions.json"))}, open("azure.json","w"))
PY
python3 raqib.py audit azure.json
```

GCP, the project IAM policy:

```
gcloud projects get-iam-policy PROJECT_ID --format=json > gcp.json
python3 raqib.py audit gcp.json
```

Kubernetes, the roles and their bindings:

```
kubectl get clusterroles,clusterrolebindings,roles,rolebindings -A -o json > k8s.json
python3 raqib.py audit k8s.json
```

For AWS you can add credential findings and write a shareable HTML report:

```
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 --decode > creds.csv
python3 raqib.py audit aws.json --credential-report creds.csv -o report.html
```

Gate a pipeline so a critical or high finding fails the build, for any cloud:

```
python3 raqib.py audit k8s.json --strict
```

Write SARIF and upload it so findings appear in the repository's security tab:

```
python3 raqib.py audit gcp.json --sarif -o raqib.sarif
```

Other options: `--cloud aws|azure|gcp|k8s` to name the cloud, `--json` for machine readable output, `--max-key-age DAYS` to set what counts as a stale AWS key, `--title` to name the report.

## What a finding means, and what it does not

A finding says what a permission would allow, not that it was used. Raqib reads configuration, not activity. It tells you that a principal could rewrite an attached policy, not that anyone did.

A clean report means the export named nothing these rules look for. It does not mean the account is secure. Raqib checks the paths it knows about; it does not prove their absence everywhere, and it does not yet read resource policies, Azure policy, or organization and folder level bindings, which can widen or narrow real access.

AWS is the deepest cloud today, with credential report findings and permissions boundary awareness. Azure, GCP, and Kubernetes cover the primary escalation, persistence, lateral movement, exfiltration, and anti forensics paths, with room to grow.

## How it works

The audit runs entirely on the file you provide. Raqib detects the cloud from the shape of the export, then reads it with that cloud's model: AWS IAM authorization details into principals with inline, attached, and group policies resolved and permissions boundaries read; Azure role assignments joined to role definitions across actions and dataActions; GCP bindings resolved to members with predefined and custom roles; Kubernetes roles resolved to subjects through their bindings, cluster wide or namespaced.

The checks are a cloud by tactic matrix under `raqib/modules`, named `{tactic}_{cloud}`, with shared helpers, the reports, and the technique mapping in `raqib/lib`, and the per cloud models in `raqib/models`. Each check tests the resolved permissions for the exposure that lets its tactic work, and separates an unconditional grant from one a scope already contains. Nothing here executes anything, and nothing leaves your machine.

For AWS, a credential report adds what the authorization details cannot show: root access keys, console users without multi factor authentication, a second active access key on a user, and access keys that are old and still active.

## License

MIT. See [LICENSE](LICENSE).
