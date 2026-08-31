# Changelog

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
