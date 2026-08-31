#!/usr/bin/env bash
# raqib.sh -- a read only lookout over your cloud access.
#
# Raqib points at the cloud you are signed in to, reads its authorization
# configuration with read only calls, and reports the moves an intruder would make
# after a foothold, each with the change that closes it. It is the defensive mirror of
# an offensive framework that runs the same six tactics across the same four clouds.
#
# Raqib never creates, changes, or deletes anything, and never reads the contents of a
# secret, object, or key. It reads who can do what, and reports it.

set -u
RAQIB_VERSION="0.14.0"
RAQIB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck disable=SC1091
. "$RAQIB_ROOT/src/lib/logger.sh"
. "$RAQIB_ROOT/src/lib/utils.sh"
. "$RAQIB_ROOT/src/lib/cloud_detect.sh"
. "$RAQIB_ROOT/src/report.sh"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/raqib.XXXXXX")"
FINDINGS="$WORKDIR/findings.jsonl"
: > "$FINDINGS"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

TACTICS=(recon privesc persist lateral exfil cleanup)
CLOUDS=(aws azure gcp k8s)

banner() {
  printf '%s' "$C_CYAN"
  printf '%s\n' \
'   ____              _  _' \
'  |  _ \ __ _  __ _ (_)| |__' \
'  | |_) / _` |/ _` || || '\''_ \' \
'  |  _ < (_| | (_| || || |_) |' \
'  |_| \_\__,_|\__, ||_||_.__/' \
'                 |_|'
  printf '%s' "$C_RESET"
  printf '  %sread only cloud exposure auditor%s   %sv%s%s\n' "$C_DIM" "$C_RESET" "$C_DIM" "$RAQIB_VERSION" "$C_RESET"
  printf '  %sreads your cloud, reports the exposure, changes nothing%s\n\n' "$C_DIM" "$C_RESET"
}

usage() {
  printf '%s\n' \
'Usage:' \
'  ./raqib.sh [scan] [--cloud aws|azure|gcp|k8s] [--strict] [--json]' \
'             scan the cloud you are signed in to, live, read only. This is the default.' \
'  ./raqib.sh scan --offline EXPORT.json [--cloud CLOUD] [--strict] [--json]' \
'             read a saved export instead of calling a cloud, for air gapped review.' \
'  ./raqib.sh scan --credentials' \
'             also read the AWS credential report: root keys, console users without a' \
'             second factor, and old keys. Needs generate-credential-report.' \
'  ./raqib.sh scan --exposure' \
'             also read S3, SQS, SNS, Lambda, Secrets Manager, and KMS resource policies for' \
'             resources left open to the public or another account.' \
'  ./raqib.sh defends' \
'             print the whole cloud by tactic map of what Raqib checks.' \
'  ./raqib.sh diff OLD.json NEW.json [--cloud CLOUD] [--strict]' \
'             scan two exports and report which findings appeared or resolved,' \
'             to catch a posture regression between two points in time.' \
'' \
'Other options:' \
'  --credential-report FILE   read a credential report CSV you already captured' \
'  --resource-policies FILE   read captured S3, SQS, SNS, Lambda, Secrets, KMS policies' \
'  --max-key-age DAYS         what counts as an old AWS access key (default 90)' \
'' \
'Notes:' \
'  Live scanning needs jq and the CLI for the cloud you scan (aws, az, gcloud, kubectl),' \
'  already signed in. Raqib only ever runs read only enumeration calls.'
}

# run every tactic module for one cloud against a gathered or saved export
analyze_cloud() {
  local cloud="$1" export_json="$2" t
  for t in "${TACTICS[@]}"; do
    analyze "$cloud" "$t" "$export_json"
  done
}

cmd_defends() {
  banner
  printf '  %sWhat Raqib checks, by cloud and tactic%s\n\n' "$C_BOLD" "$C_RESET"
  local descriptions=(
    "recon|Reconnaissance|the mapping an intruder does first"
    "privesc|Privilege escalation|turning access into more"
    "persist|Persistence|planting something to keep the access"
    "lateral|Lateral movement|reaching the next principal"
    "exfil|Exfiltration|the permission to pull data out"
    "cleanup|Defense evasion|weakening the record that would show it"
  )
  local row t label desc c present
  for row in "${descriptions[@]}"; do
    IFS='|' read -r t label desc <<<"$row"
    printf '  %s%-22s%s %s\n' "$C_CYAN" "$label" "$C_RESET" "$desc"
    printf '    '
    for c in "${CLOUDS[@]}"; do
      if [ -f "$RAQIB_ROOT/src/modules/${t}_${c}.sh" ]; then present="$C_GREEN$c$C_RESET"; else present="$C_DIM$c$C_RESET"; fi
      printf '%b  ' "$present"
    done
    printf '\n\n'
  done
  printf '  %sModules live in src/modules as {tactic}_{cloud}.sh, the shared models in%s\n' "$C_DIM" "$C_RESET"
  printf '  %ssrc/lib as model_{cloud}.jq, mirroring the offensive framework module for module.%s\n\n' "$C_DIM" "$C_RESET"
}

cmd_scan() {
  local forced_cloud="" offline="" strict=0 as_json=0 creds_live=0 cred_csv="" maxage=90 exposure_live=0 rp_file=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --cloud) forced_cloud="$2"; shift 2 ;;
      --offline) offline="$2"; shift 2 ;;
      --strict) strict=1; shift ;;
      --json) as_json=1; shift ;;
      --credentials) creds_live=1; shift ;;
      --credential-report) cred_csv="$2"; shift 2 ;;
      --max-key-age) maxage="$2"; shift 2 ;;
      --exposure) exposure_live=1; shift ;;
      --resource-policies) rp_file="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) log_error "unknown option: $1"; usage; exit 2 ;;
    esac
  done

  [ "$as_json" -eq 1 ] || banner

  local targets=()
  if [ -n "$offline" ]; then
    [ -f "$offline" ] || { log_error "no such file: $offline"; exit 2; }
    local c="$forced_cloud"
    [ -n "$c" ] || c="$(detect_from_file "$offline")"
    [ -n "$c" ] || { log_error "could not tell which cloud this export is from. pass --cloud."; exit 2; }
    cp "$offline" "$(export_path_for "$c")"
    targets=("$c")
  elif [ -n "$forced_cloud" ]; then
    targets=("$forced_cloud")
    "gather_${forced_cloud}" || { log_error "could not read $forced_cloud. is the CLI signed in?"; exit 2; }
  else
    mapfile -t targets < <(detect_clouds)
    if [ "${#targets[@]}" -eq 0 ]; then
      log_error "no cloud is signed in here. sign in to aws, az, gcloud, or kubectl, or pass --offline EXPORT.json --cloud CLOUD."
      exit 2
    fi
    log_info "scanning: ${targets[*]}"
    local c
    for c in "${targets[@]}"; do "gather_${c}" || log_warn "could not read $c, skipping"; done
  fi

  # the AWS credential report is a separate read only input. gather it live only when
  # asked, since it needs generate-credential-report; or read one already captured.
  if [ "$creds_live" -eq 1 ] && [ -z "$cred_csv" ]; then
    if printf '%s\n' "${targets[@]}" | grep -qx aws; then
      gather_aws_credentials && cred_csv="$WORKDIR/aws-credentials.csv"
    fi
  fi

  # resource policies (S3, KMS): gather live with --exposure, or read a captured file
  if [ "$exposure_live" -eq 1 ] && [ -z "$rp_file" ]; then
    if printf '%s\n' "${targets[@]}" | grep -qx aws; then
      gather_aws_exposure && rp_file="$WORKDIR/aws-resource-policies.json"
    fi
  fi

  local c ep
  for c in "${targets[@]}"; do
    ep="$(export_path_for "$c")"
    [ -f "$ep" ] || continue
    analyze_cloud "$c" "$ep"
    if [ "$c" = "aws" ] && [ -n "$cred_csv" ] && [ -f "$cred_csv" ]; then
      . "$RAQIB_ROOT/src/modules/credentials_aws.sh"
      analyze_credentials_aws "$cred_csv" "$maxage" 2>/dev/null | jq -c '.[]?' >> "$FINDINGS" 2>/dev/null || true
    fi
    if [ "$c" = "aws" ] && [ -n "$rp_file" ] && [ -f "$rp_file" ]; then
      . "$RAQIB_ROOT/src/modules/exposure_aws.sh"
      analyze_exposure_aws "$rp_file" 2>/dev/null | jq -c '.[]?' >> "$FINDINGS" 2>/dev/null || true
    fi
  done

  if [ "$as_json" -eq 1 ]; then
    report_json
  else
    for c in "${targets[@]}"; do report_terminal "$c"; done
  fi

  if [ "$strict" -eq 1 ]; then
    if grep -q '"severity":"critical"' "$FINDINGS" || grep -q '"severity":"high"' "$FINDINGS"; then
      exit 1
    fi
  fi
}

render_diff_line() {
  local sign="$1" color="$2" line="$3" sev title name kind
  sev=$(jq -r '.severity' <<<"$line"); title=$(jq -r '.title' <<<"$line")
  name=$(jq -r '.principal.name' <<<"$line"); kind=$(jq -r '.principal.kind' <<<"$line")
  printf '  %s%s%s %s[%s]%s %s%s%s  %s(%s %s)%s\n' \
    "$color" "$sign" "$C_RESET" "$C_DIM" "$sev" "$C_RESET" "$C_BOLD" "$title" "$C_RESET" "$C_DIM" "$kind" "$name" "$C_RESET"
}

report_diff() {
  local cloud="$1" dj="$2" na nr nu
  na=$(jq '.added|length' <<<"$dj"); nr=$(jq '.removed|length' <<<"$dj"); nu=$(jq '.unchanged' <<<"$dj")
  printf '\n  %s%s posture diff%s\n' "$C_BOLD" "$(echo "$cloud" | tr '[:lower:]' '[:upper:]')" "$C_RESET"
  printf '  %s%s new   %s resolved   %s unchanged%s\n\n' "$C_DIM" "$na" "$nr" "$nu" "$C_RESET"
  if [ "$na" -eq 0 ] && [ "$nr" -eq 0 ]; then
    printf '  %sNo change in the findings between these two exports.%s\n\n' "$C_GREEN" "$C_RESET"
    return 0
  fi
  if [ "$na" -gt 0 ]; then
    printf '  %s%sNew findings, exposure that appeared since the first export%s\n' "$C_BOLD" "$C_RED" "$C_RESET"
    jq -c '.added[]' <<<"$dj" | while IFS= read -r line; do render_diff_line "+" "$C_RED" "$line"; done
    printf '\n'
  fi
  if [ "$nr" -gt 0 ]; then
    printf '  %s%sResolved findings, exposure that is gone in the second export%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
    jq -c '.removed[]' <<<"$dj" | while IFS= read -r line; do render_diff_line "-" "$C_GREEN" "$line"; done
    printf '\n'
  fi
}

# diff two exports: scan each, then report which findings appeared or resolved. This
# is how a posture regression is caught between two points in time. Read only.
cmd_diff() {
  local as_json=0 strict=0 forced_cloud="" old="" new="" pass=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) as_json=1; shift ;;
      --strict) strict=1; shift ;;
      --cloud) forced_cloud="$2"; shift 2 ;;
      --credentials|--exposure) pass+=("$1"); shift ;;
      --credential-report|--resource-policies|--max-key-age) pass+=("$1" "$2"); shift 2 ;;
      -h|--help) usage; exit 0 ;;
      -*) log_error "unknown option: $1"; usage; exit 2 ;;
      *) if [ -z "$old" ]; then old="$1"; elif [ -z "$new" ]; then new="$1";
         else log_error "diff takes two files: OLD.json NEW.json"; exit 2; fi; shift ;;
    esac
  done
  [ -n "$old" ] && [ -n "$new" ] || { log_error "usage: raqib.sh diff OLD.json NEW.json [--cloud CLOUD] [--json] [--strict]"; exit 2; }
  [ -f "$old" ] || { log_error "no such file: $old"; exit 2; }
  [ -f "$new" ] || { log_error "no such file: $new"; exit 2; }
  local co cn
  co="$forced_cloud"; [ -n "$co" ] || co="$(detect_from_file "$old")"
  cn="$forced_cloud"; [ -n "$cn" ] || cn="$(detect_from_file "$new")"
  [ -n "$co" ] && [ -n "$cn" ] || { log_error "could not tell which cloud these exports are from. pass --cloud."; exit 2; }
  [ "$co" = "$cn" ] || { log_error "the two exports are from different clouds ($co and $cn). diff compares one cloud."; exit 2; }

  local oldf newf
  oldf="$WORKDIR/_diff_old.json"; newf="$WORKDIR/_diff_new.json"
  bash "$RAQIB_ROOT/raqib.sh" scan --offline "$old" --cloud "$co" --json "${pass[@]}" > "$oldf" 2>/dev/null || echo '[]' > "$oldf"
  bash "$RAQIB_ROOT/raqib.sh" scan --offline "$new" --cloud "$cn" --json "${pass[@]}" > "$newf" 2>/dev/null || echo '[]' > "$newf"

  local dj
  dj="$(jq -n --slurpfile o "$oldf" --slurpfile n "$newf" '
    def key: (.tactic + "|" + .title + "|" + (.principal.arn // ""));
    ($o[0] // []) as $old | ($n[0] // []) as $new
    | ($old | map(key)) as $ok
    | ($new | map(key)) as $nk
    | { added:   [ $new[] | select((.|key) as $k | ($ok | index($k)) | not) ],
        removed: [ $old[] | select((.|key) as $k | ($nk | index($k)) | not) ],
        unchanged: ([ $new[] | select((.|key) as $k | ($ok | index($k))) ] | length) }')"

  if [ "$as_json" -eq 1 ]; then
    jq -n --argjson d "$dj" '$d'
  else
    report_diff "$co" "$dj"
  fi

  if [ "$strict" -eq 1 ] && [ "$(jq '.added|length' <<<"$dj")" -gt 0 ]; then
    exit 1
  fi
}

main() {
  local sub="${1:-scan}"
  case "$sub" in
    defends) cmd_defends ;;
    diff) shift || true; cmd_diff "$@" ;;
    scan) shift || true; cmd_scan "$@" ;;
    -h|--help) banner; usage ;;
    --*) cmd_scan "$@" ;;
    *) log_error "unknown command: $sub"; usage; exit 2 ;;
  esac
}
main "$@"
