#!/usr/bin/env python3
"""The Raqib command line.

  raqib audit <authorization-details.json> [options]

Read an IAM export and report the exposure in it. The export is the JSON that
`aws iam get-account-authorization-details` produces, saved to a file. Raqib does
not call AWS. It reads the file and reasons about it offline.
"""

import argparse
import json
import sys

from . import __version__, audit, model
from . import report as report_mod
from . import rules as rules_mod


def _load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def cmd_audit(args):
    try:
        auth = _load_json(args.export)
    except FileNotFoundError:
        sys.stderr.write("raqib: no such file: " + args.export + "\n")
        return 2
    except json.JSONDecodeError as exc:
        sys.stderr.write("raqib: the export is not valid JSON: " + str(exc) + "\n")
        return 2

    cred_csv = None
    if args.credential_report:
        try:
            with open(args.credential_report, "r", encoding="utf-8") as fh:
                cred_csv = fh.read()
        except FileNotFoundError:
            sys.stderr.write("raqib: no such credential report: " + args.credential_report + "\n")
            return 2

    try:
        findings, summary, acct = audit(auth, credential_report_csv=cred_csv, max_key_age_days=args.max_key_age)
    except (ValueError, KeyError) as exc:
        sys.stderr.write("raqib: could not read the export: " + str(exc) + "\n")
        return 2

    meta = {"title": args.title or "IAM exposure report", "source": args.export}

    if args.json:
        sys.stdout.write(report_mod.as_json(findings, summary, meta) + "\n")
    elif args.sarif:
        out = report_mod.sarif(findings, meta)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out)
            sys.stdout.write("wrote " + args.output + "\n")
        else:
            sys.stdout.write(out + "\n")
    elif args.html:
        html = report_mod.html_report(findings, summary, meta)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(html)
            sys.stdout.write("wrote " + args.output + "\n")
        else:
            sys.stdout.write(html)
    else:
        report_mod.terminal(findings, summary, meta, sys.stdout)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report_mod.html_report(findings, summary, meta))
            sys.stdout.write("\nwrote " + args.output + "\n")

    if args.strict and (summary["counts"]["critical"] > 0 or summary["counts"]["high"] > 0):
        return 1
    return 0


def cmd_paths(args):
    """List the escalation paths Raqib looks for."""
    print("Privilege escalation paths Raqib checks:\n")
    for m in rules_mod.PRIVESC_METHODS:
        actions = ", ".join(m["actions"])
        print("  " + m["id"])
        print("    needs: " + actions)
        print("    " + m["enables"])
        print()
    print("It also checks role trust policies for principals that are public,")
    print("cross account, or federated without a condition, and flags wildcard")
    print("permissions on sensitive services.")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="raqib",
        description="Read only AWS IAM exposure auditor. Reads an IAM export and reports the privilege escalation paths, trust risks, and wildcard permissions in it.",
        epilog="Produce the export with: aws iam get-account-authorization-details > export.json",
    )
    p.add_argument("--version", action="version", version="raqib " + __version__)
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("audit", help="audit an IAM export")
    a.add_argument("export", help="path to get-account-authorization-details JSON")
    a.add_argument("--credential-report", metavar="CSV", help="an IAM credential report CSV, for stale key and MFA findings")
    a.add_argument("--max-key-age", type=int, default=90, metavar="DAYS", help="access key age that counts as stale (default 90)")
    a.add_argument("--json", action="store_true", help="write the findings as JSON")
    a.add_argument("--sarif", action="store_true", help="write SARIF for upload to code scanning")
    a.add_argument("--html", action="store_true", help="write a self contained HTML report to stdout")
    a.add_argument("-o", "--output", metavar="FILE", help="also write an HTML report to this file")
    a.add_argument("--title", help="a title for the report")
    a.add_argument("--strict", action="store_true", help="exit 1 when a critical or high finding is present")
    a.set_defaults(func=cmd_audit)

    paths = sub.add_parser("paths", help="list the escalation paths Raqib checks")
    paths.set_defaults(func=cmd_paths)

    defends = sub.add_parser("defends", help="show which attacker tactics Raqib covers")
    defends.set_defaults(func=cmd_defends)

    return p


COVERAGE = [
    ("reconnaissance", "partial",
     "Flags full control of a sensitive service through a wildcard, the broad visibility used to map an account."),
    ("privilege escalation", "covered",
     "The known IAM escalation paths, administrator by wildcard or attached policy, and service wildcards, read with permissions boundary awareness."),
    ("persistence", "partial",
     "Flags the create credential and login profile paths that establish a foothold, and users carrying two active access keys."),
    ("lateral movement", "covered",
     "Role trust policies that are assumable by anyone, trust an external account, or federate without a condition."),
    ("exfiltration", "planned",
     "Needs resource policies such as S3 bucket and KMS key policies, which are not in the authorization details. This is the next area to add."),
    ("defense evasion", "covered",
     "Principals, beyond the administrators already flagged, that can stop or delete CloudTrail, Config, GuardDuty, log groups, and Security Hub."),
]


def cmd_defends(args):
    print("What Raqib watches for, by attacker tactic:\n")
    for tactic, state, text in COVERAGE:
        print("  " + tactic + "  [" + state + "]")
        print("    " + text)
        print()
    print("Raqib reads an AWS IAM export offline. It reports the paths, not the use of them,")
    print("and a clean report means the export named nothing these rules look for.")
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
