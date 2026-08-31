# Changelog

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
