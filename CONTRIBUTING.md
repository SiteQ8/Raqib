# Contributing to Raqib

Thank you for helping make Raqib a better lookout. It stays small and sharp, so a few things keep it that way.

## The shape of the project

Raqib reads IAM and RBAC across AWS, Azure, GCP, and Kubernetes with read only calls and reports the exposure in each. There are two paths that share one finding taxonomy, so a finding reads the same whichever ran it.

The bash scanner is the primary path. `raqib.sh` detects the cloud, gathers its authorization configuration with read only calls, and runs the checks over it. The models live in `src/lib` as `model_{cloud}.jq`, one per cloud, and resolve the raw export into principals with their effective permissions. The checks are a cloud by tactic matrix in `src/modules`, named `{tactic}_{cloud}.sh`, and the report is in `src/report.sh`. The cloud detection, the logging, and the shared shell helpers are in `src/lib`.

The Python engine under `raqib/` mirrors the same layout for the offline and SARIF path: a model per cloud in `raqib/models`, the checks in `raqib/modules` as `{tactic}_{cloud}.py`, the shared helpers, the report, and the technique mapping in `raqib/lib`, and the command line in `raqib/__main__.py`.

## Adding a check

Put it in the tactic module it belongs to, for the cloud it applies to, and add it to both paths, the `{tactic}_{cloud}.sh` module and its `{tactic}_{cloud}.py` twin, so the scanner and the engine stay in lockstep. A check reads a principal's effective permissions through that cloud's model, which already understands the cloud's own grant semantics and lets an explicit Deny win, and returns findings built with the shared helper. Give each finding a severity, the principal it names, the move it enables, the fix that closes it, and let the technique mapping tag it. Prefer to flag an unconditional grant over one a scope already contains, and lower a finding when a permissions boundary or its equivalent would cap it.

## Two firm rules

Raqib has zero dependencies. The Python engine uses the standard library and nothing else; the bash scanner uses `jq` and the cloud CLI you are already signed in to. Please keep it that way.

Human readable text, in the README, the reports, and finding messages, uses no hyphen joined words and no dashes. Write zero dependency, not the hyphen joined form. Action names and flags such as iam:PassRole and --strict are technical tokens and are fine as they are.

## Before you open a pull request

Run the tests:

```
python3 -m unittest discover -s tests
```

The suite drives `raqib.sh` over every sample and asserts it produces the same findings as the Python engine, so the two paths cannot drift apart. Add tests for what you changed. A new check should prove that it fires on a weak example and stays quiet on a least privilege one, so it does not cry wolf.
