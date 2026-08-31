#!/usr/bin/env python3
"""The Raqib command line.

  raqib audit <export.json> [--cloud aws|azure|gcp|k8s] [options]

Read a cloud authorization export and report the exposure in it. Raqib detects which
cloud the export is from and reads it offline. It never calls a cloud.
"""

import argparse
import json
import sys

from . import __version__, audit
from .lib import report as report_mod
from .lib import detect
from .modules import privesc_aws

BANNER = r"""
  ____                 _   _
 |  _ \    __ _   __ _ (_) | |__
 | |_) |  / _` | / _` || | | '_ \
 |  _ <  | (_| || (_| || | | |_) |
 |_| \_\  \__,_| \__, ||_| |_.__/
                    |_|   read only cloud exposure auditor
"""


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
        findings, summary, acct = audit(auth, cloud=args.cloud, credential_report_csv=cred_csv, max_key_age_days=args.max_key_age)
    except (ValueError, KeyError) as exc:
        sys.stderr.write("raqib: could not read the export: " + str(exc) + "\n")
        return 2

    cloud = summary.get("cloud", "")
    default_title = (cloud.upper() + " exposure report") if cloud else "Cloud exposure report"
    meta = {"title": args.title or default_title, "source": args.export, "cloud": cloud}

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


def _finding_key(f):
    p = f.get("principal") or {}
    return f.get("tactic", "") + "|" + f.get("title", "") + "|" + (p.get("arn") or "")


def cmd_diff(args):
    """Scan two exports and report which findings appeared or resolved between them."""
    try:
        old = _load_json(args.old)
        new = _load_json(args.new)
    except FileNotFoundError as exc:
        sys.stderr.write("raqib: no such file: " + str(exc) + "\n")
        return 2
    except json.JSONDecodeError as exc:
        sys.stderr.write("raqib: an export is not valid JSON: " + str(exc) + "\n")
        return 2
    try:
        of, osum, _ = audit(old, cloud=args.cloud)
        nf, nsum, _ = audit(new, cloud=args.cloud)
    except (ValueError, KeyError) as exc:
        sys.stderr.write("raqib: could not read an export: " + str(exc) + "\n")
        return 2
    if osum.get("cloud") != nsum.get("cloud"):
        sys.stderr.write("raqib: the two exports are from different clouds. diff compares one cloud.\n")
        return 2

    ok = {_finding_key(f) for f in of}
    nk = {_finding_key(f) for f in nf}
    added = [f for f in nf if _finding_key(f) not in ok]
    removed = [f for f in of if _finding_key(f) not in nk]
    unchanged = len([f for f in nf if _finding_key(f) in ok])

    if args.json:
        sys.stdout.write(json.dumps({"added": added, "removed": removed, "unchanged": unchanged}, indent=2) + "\n")
    else:
        cloud = nsum.get("cloud", "")
        print("\n  " + cloud.upper() + " posture diff")
        print("  %d new   %d resolved   %d unchanged\n" % (len(added), len(removed), unchanged))
        if not added and not removed:
            print("  No change in the findings between these two exports.\n")
        else:
            if added:
                print("  New findings, exposure that appeared since the first export")
                for f in added:
                    print("  + [%s] %s  (%s %s)" % (f["severity"], f["title"], f["principal"]["kind"], f["principal"]["name"]))
                print()
            if removed:
                print("  Resolved findings, exposure that is gone in the second export")
                for f in removed:
                    print("  - [%s] %s  (%s %s)" % (f["severity"], f["title"], f["principal"]["kind"], f["principal"]["name"]))
                print()

    if args.strict and added:
        return 1
    return 0


def cmd_paths(args):
    """List the escalation paths Raqib looks for."""
    print("Privilege escalation paths Raqib checks:\n")
    print("These are the AWS IAM paths. Run defends for the full cloud by tactic map.\n")
    for m in privesc_aws.PRIVESC_METHODS:
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
        description="Read only cloud exposure auditor for AWS, Azure, GCP, and Kubernetes. Reads an authorization export and reports the moves an intruder would make after a foothold.",
        epilog="AWS: aws iam get-account-authorization-details > export.json  |  see the README for Azure, GCP, and Kubernetes",
    )
    p.add_argument("--version", action="version", version="raqib " + __version__)
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("audit", help="audit a cloud authorization export")
    a.add_argument("export", help="path to the export JSON (AWS, Azure, GCP, or Kubernetes)")
    a.add_argument("--cloud", choices=["aws", "azure", "gcp", "k8s"], help="which cloud the export is from (detected when omitted)")
    a.add_argument("--credential-report", metavar="CSV", help="an AWS IAM credential report CSV, for stale key and MFA findings")
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

    d = sub.add_parser("diff", help="diff two exports and report findings that appeared or resolved")
    d.add_argument("old", help="the earlier export")
    d.add_argument("new", help="the later export")
    d.add_argument("--cloud", choices=["aws", "azure", "gcp", "k8s"], help="which cloud the exports are from (detected when omitted)")
    d.add_argument("--json", action="store_true", help="write the diff as JSON")
    d.add_argument("--strict", action="store_true", help="exit 1 when a finding appeared")
    d.set_defaults(func=cmd_diff)

    defends = sub.add_parser("defends", help="show which attacker tactics Raqib covers")
    defends.set_defaults(func=cmd_defends)

    return p


COVERAGE = [
    ("recon", "reconnaissance",
     {"aws": "the call that dumps the whole IAM configuration, and broad enumeration",
      "azure": "Reader across a management group, and reading all role assignments",
      "gcp": "Viewer over the project, a full read of every resource",
      "k8s": "list or get across every namespace, a full map of the cluster"}),
    ("privesc", "privilege escalation",
     {"aws": "the known IAM escalation paths, administrator, and service wildcards, with boundary awareness",
      "azure": "Owner, writing role assignments or role definitions, elevateAccess, and running as a managed identity via a VM, a runbook, or an identity assignment",
      "gcp": "Owner, setIamPolicy, impersonation and signing, acting as a service account to deploy on Cloud Functions, Compute, or Cloud Run, rewriting a custom role, and running as the Cloud Build or Deployment Manager service account",
      "k8s": "cluster-admin, the escalate, bind, and impersonate verbs, creating pods or the workloads that create them, exec into pods, minting service account tokens, and self approving certificate requests"}),
    ("persist", "persistence",
     {"aws": "creating a user or role and granting it access, and a second active access key",
      "azure": "federated credentials on a managed identity, new managed identities, Automation accounts, and standing role assignments",
      "gcp": "service account keys and service accounts, granting lasting access to a service account, and scheduled jobs",
      "k8s": "cluster role bindings, role bindings, service accounts, and admission webhooks"}),
    ("lateral", "lateral movement",
     {"aws": "role trust that is public, cross account, or federated without a condition",
      "azure": "a service principal with reach across a subscription or higher, and an identity that spans multiple subscriptions",
      "gcp": "a role granted to everyone, a default service account with a broad role, and a group holding Owner or Editor",
      "k8s": "reading secrets across the cluster, reaching the kubelet on nodes, and port forwarding to pods"}),
    ("exfil", "exfiltration",
     {"aws": "reading every secret, object, parameter, or key, and sharing a snapshot out",
      "azure": "listing storage keys, and reading Key Vault secret values",
      "gcp": "reading Cloud Storage, Secret Manager, and BigQuery broadly",
      "k8s": "reading config maps and secrets across the cluster"}),
    ("cleanup", "anti forensics",
     {"aws": "stopping or deleting CloudTrail, Config, GuardDuty, log groups, or Security Hub",
      "azure": "deleting diagnostic settings and Log Analytics workspaces",
      "gcp": "deleting log sinks and logs",
      "k8s": "deleting events and admission webhook configurations"}),
]


def cmd_defends(args):
    print(BANNER)
    print("S7aba runs offence across four clouds in six module families. Raqib reads the")
    print("same clouds for the defensive side of each tactic. The module names match:\n")
    print("  raqib/modules/{tactic}_{cloud}.py     mirrors     src/modules/{tactic}_{cloud}.sh\n")
    clouds = ["aws", "azure", "gcp", "k8s"]
    for module, tactic, per in COVERAGE:
        print("  " + tactic + "   (" + module + "_*)")
        for c in clouds:
            print("    " + c.ljust(6) + " " + per[c])
        print()
    print("Raqib reads an export offline. It reports the paths, not the use of them, and a")
    print("clean report means the export named nothing these rules look for.")
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        sys.stdout.write(BANNER + "\n")
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
