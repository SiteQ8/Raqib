# Contributing to Raqib

Thank you for helping make Raqib a better lookout. It stays small and sharp, so a few things keep it that way.

## The shape of the project

Raqib reads an AWS IAM export and reports the exposure in it. The checks live in `raqib/checks`, organized by attacker tactic to mirror the offensive side one for one: `recon`, `privesc`, `persist`, `lateral`, `exfil`, and `cleanup`. Each module exports a check function that takes a resolved account and returns findings. The model that resolves an export into principals is in `raqib/model.py`, the reports are in `raqib/report.py`, and the command line is in `raqib/__main__.py`.

## Adding a check

Put it in the tactic module it belongs to. A check reads a principal's effective permissions through the account model, which already understands IAM wildcards and lets an explicit Deny win, and returns findings built with the shared helper. Give each finding a severity, the principal it names, the move it enables, the fix that closes it, and let the technique mapping tag it. Prefer to flag an unconditional grant on resource * over one a resource restriction may already contain, and lower a finding when a permissions boundary would cap it.

## Two firm rules

Raqib has zero dependencies. It uses the Python standard library and nothing else. Please keep it that way.

Human readable text, in the README, the reports, and finding messages, uses no hyphen joined words and no dashes. Write zero dependency, not the hyphen joined form. Action names and flags such as iam:PassRole and --strict are technical tokens and are fine as they are.

## Before you open a pull request

Run the tests:

```
python3 -m unittest discover -s tests
```

Add tests for what you changed. A new check should prove that it fires on a weak example and stays quiet on a least privilege one, so it does not cry wolf.
