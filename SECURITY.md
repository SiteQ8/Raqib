# Security policy

Raqib is a read only auditor. Every call it makes is a read: it lists and describes the authorization configuration of the cloud you are signed in to, across AWS, Azure, GCP, and Kubernetes, and nothing more. It never creates, changes, or deletes anything, and it never reads the contents of a secret, an object, or a key. A guard refuses any command that is not one of the read only gather calls, so running Raqib does not put an account at risk.

## Reporting a problem in Raqib itself

If you find a bug in Raqib, a false result, a case it reads wrong, or anything that could mislead a defender, please open an issue on the repository. If you would rather report privately, note that in the issue and we will find a private channel.

Raqib handles your authorization configuration, and with `--credentials` an AWS credential report, and with `--exposure` S3 and KMS resource policies. Treat all of these as sensitive. Do not paste a real export, credential report, or resource policy into a public issue. A trimmed, made up example that shows the problem is enough.

## What Raqib does not claim

A finding says what a permission would allow, not that it was used. Raqib reads authorization configuration, not activity. A clean report means the configuration named nothing these rules look for, not that the account is secure.

Raqib reads IAM and RBAC across all four clouds, and for AWS it also reads S3 and KMS resource policies with `--exposure`. It does not yet read other resource policies, Azure Policy, service control policies, or organization and folder level bindings, which can widen or narrow real access. AWS is the deepest coverage today, with permissions boundary awareness across the escalation paths; the other three cover the primary paths and have room to grow.
