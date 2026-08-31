# Changelog

## 0.10.0

Deeper persistence coverage on Azure, GCP, and Kubernetes, bringing each closer to the AWS depth. The bash scanner and the Python engine gain the checks together.

- Azure: adding a federated identity credential to a managed identity, which lets an external OIDC issuer authenticate as it with no secret to rotate, and creating an Automation account, a durable scheduled execution surface. Creating managed identities and planting role assignments are kept
- GCP: setting the IAM policy on a service account to bind a controlled principal as a token creator, a stealthy back door, and planting a Cloud Scheduler job that re-triggers a callback. Service account keys and service accounts are kept
- Kubernetes: creating role bindings across namespaces and creating service accounts, alongside the cluster role bindings and admission webhooks already covered
- New sample principals and six tests. 127 tests, the two engines still in lockstep


## 0.9.0

Deeper escalation coverage on two more clouds, a wider exposure scan, and a new diff command.

- Azure privilege escalation: running code on a VM through runCommand or an extension, running an Automation runbook, and assigning a user assigned managed identity, each executing as that identity, plus the roleDefinitions/write check that had only been in the Python engine
- Kubernetes privilege escalation: creating the workload controllers that spawn pods, exec and attach into running pods, minting service account tokens, and self approving a certificate signing request to authenticate as anyone
- AWS --exposure now reads SQS queue, SNS topic, Lambda function, and Secrets Manager secret resource policies as well as S3 and KMS, flagging any left open to the public or another account. The read only gather allowlist gains the matching list and get calls
- New diff command: scan two exports and report which findings appeared and which resolved, to catch a posture regression between two points in time. In both the bash scanner and the Python engine, with --strict for a pipeline that fails on new exposure
- 121 tests, the bash scanner and the Python engine still in lockstep


## 0.8.0

Deeper GCP privilege escalation. GCP privesc now reads the documented escalation paths, not just Owner and impersonation, bringing it closer to the AWS depth.

- Acting as a service account to deploy a resource that then runs as it, the GCP form of passing a role, across Cloud Functions, Compute Engine, and Cloud Run, reported per target, with the generic actAs finding kept as the fallback when no deploy permission is paired with it
- Rewriting a custom role that is granted to the member, so it can add permissions to itself
- Running as a powerful default service account: starting a Cloud Build build runs as the Cloud Build service account, and creating a Deployment Manager deployment runs as the Google APIs service account, both Editor on the project by default
- Impersonation now also catches signing as a service account and minting OpenID tokens, not only access tokens
- New sample principals and six tests for the added paths; the bash scanner and the Python engine still produce the same findings, as the parity test asserts. 109 tests


## 0.7.0

Raqib now reads resource policies, the exposure the IAM export cannot show. An IAM grant is who is allowed to do what; a resource policy is a bucket or a key left open to the world regardless of any identity. For AWS, Raqib now reads both.

- New exposure_aws module: an S3 bucket open to the public through its bucket policy, a bucket that grants another account access, a bucket that allows the public only under a condition, a bucket without a full public access block, a KMS key policy that allows any principal, and a key policy that trusts an external account
- A --exposure flag gathers S3 and KMS resource policies live, read only (list buckets and keys, get their policies, get the public access block); --resource-policies reads a captured file
- This closes the gap noted since the first release: exfiltration read the permission to move data, and now Raqib also reads the resource left open to the public
- New test that asserts the exposure findings on the sample, so the behavior is pinned. 103 tests
- The browser explorer shows the exposure findings in the AWS view, 27 findings

## 0.6.0

The bash scanner now reads the AWS credential report, so its AWS coverage matches the Python engine: not just what IAM policy allows, but the credential hygiene the policy cannot show.

- New credentials_aws module: flags a root account with an active access key or no multi factor authentication, a console user without a second factor, a user with two active keys, and an access key that is old and still active
- A --credentials flag gathers the report live (read only: generate and get, which describes the account and changes no principal), and --credential-report reads one you already captured
- A --max-key-age flag sets what counts as an old key, ninety days by default
- New test that drives raqib.sh over every sample and asserts it matches the Python engine, credential report included, so the two paths cannot drift apart
- The browser explorer now shows the credential findings in the AWS view

## 0.5.0

Raqib is now a bash tool that scans your cloud. Point it at the cloud you are signed in to and it reads your live authorization configuration with read only calls, no file to export and hand over, mirroring the offensive framework it defends against.

- New launcher raqib.sh: detects the cloud, gathers its authorization configuration with read only calls, and reports, all in one step
- Reads live across AWS, Azure, GCP, and Kubernetes, with a guard that refuses any call that is not one of the read only gather calls
- The analysis is pure bash and jq: models in src/lib as model_{cloud}.jq, checks in src/modules as {tactic}_{cloud}.sh, the same cloud by tactic matrix as before
- Validated to produce the same findings as the Python engine across every sample, all four clouds
- A defends command that prints the whole cloud by tactic map, and a --strict mode that exits non zero on a critical or high finding
- The file workflow is now secondary: --offline reads a saved export for air gapped review, and the Python engine stays for SARIF and the AWS credential report

## 0.4.0

Raqib is now a cloud tool, not an AWS tool, and it is organized as a cloud by tactic matrix that mirrors S7aba module for module.

- Multi cloud: reads AWS, Azure, GCP, and Kubernetes, detecting the cloud from the shape of the export
- Restructured into raqib/lib for shared helpers, reports, and the technique mapping, raqib/models for a model per cloud, and raqib/modules for the checks
- The checks are named {tactic}_{cloud}, twenty four modules matching S7aba's src/modules one for one
- New per cloud models: Azure RBAC role assignments and definitions, GCP IAM policy bindings with predefined and custom roles, Kubernetes roles and bindings
- New checks across all six tactics for Azure, GCP, and Kubernetes
- A --cloud flag, cloud auto detection, and a defends command that prints the whole cloud by tactic map
- Sample exports and tests for every cloud, 98 tests

## 0.3.0

Raqib is now built as the mirror of an offensive toolkit, its checks organized by the six attacker tactics so the defense maps onto the offense one for one.

- Checks are split into one module per tactic under raqib/checks: recon, privesc, persist, lateral, exfil, and cleanup
- New reconnaissance check: flags the call that dumps the entire IAM configuration, and broad identity enumeration
- New exfiltration check: flags the permission to read every secret, object, parameter, or key, and to share a snapshot out of the account
- New persistence check: flags principals that can create a new user or role and grant it access
- A banner, and a defends command that maps each S7aba module family to what Raqib covers
- Contributor, security, and conduct guides, and a banner image
- 73 tests

## 0.2.0

Broader coverage of the tactics an intruder uses after a foothold, plus reporting that ties each finding to the technique it defends against.

- New detection for audit trail tampering: principals, beyond the administrators already flagged, that can stop or delete CloudTrail, Config, GuardDuty, log groups, or Security Hub
- Permissions boundary awareness: a finding is lowered when an attached boundary would cap the escalation it describes, and says so
- A second active access key on a user is now flagged as a persistence footprint
- Every finding carries its MITRE ATT&CK technique, shown in the terminal and HTML reports
- SARIF output with --sarif, for upload to code scanning and the repository security tab
- A new defends command that shows which attacker tactics Raqib covers
- More samples and 59 tests

## 0.1.0

First release.

Raqib reads an AWS IAM authorization details export and reports the exposure in it, entirely offline.

- Resolves each principal's effective permissions across inline, attached managed, and group policies, with an IAM wildcard matcher and Deny precedence
- Detects the known IAM privilege escalation paths, including policy rewrites, administrator attachment, login profile and access key abuse, group and trust policy changes, and passing a role to EC2, Lambda, Glue, CloudFormation, Data Pipeline, SageMaker, and CodeBuild
- Reads role trust policies for principals that are public, cross account, or federated without a condition
- Flags administrator by wildcard and full control of a sensitive service through a service wildcard
- Optional credential report analysis for root access keys, console users without multi factor authentication, and stale active access keys
- Terminal, JSON, and self contained HTML reports
- A strict mode that exits non zero on a critical or high finding, for use in a pipeline
- Zero dependencies, Python 3.8 or newer
