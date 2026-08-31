# Security policy

Raqib is a read only auditor. It never calls AWS and never touches an account. It reads a file you export and reasons about it offline, so running Raqib does not put an account at risk.

## Reporting a problem in Raqib itself

If you find a bug in Raqib, a false result, a case it reads wrong, or anything that could mislead a defender, please open an issue on the repository. If you would rather report privately, note that in the issue and we will find a private channel.

Because Raqib handles an IAM export, treat that export as sensitive. Do not paste a real export or a real credential report into a public issue. A trimmed, made up example that shows the problem is enough.

## What Raqib does not claim

A finding says what a permission would allow, not that it was used. A clean report means the export named nothing these rules look for, not that the account is secure. Raqib reads AWS IAM today and does not yet read resource policies, service control policies, or permissions boundaries beyond the boundary attached to a principal.
