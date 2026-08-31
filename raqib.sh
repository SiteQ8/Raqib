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
RAQIB_VERSION="0.5.0"
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
  cat <<'ART'
   ____              _  _
  |  _ \ __ _  __ _ (_)| |__
  | |_) / _` |/ _` || || '_ \
  |  _ < (_| | (_| || || |_) |
  |_| \_\__,_|\__, ||_||_.__/
                 |_|
ART
  printf '%s' "$C_RESET"
  printf '  %sread only cloud exposure auditor%s   %sv%s%s\n' "$C_DIM" "$C_RESET" "$C_DIM" "$RAQIB_VERSION" "$C_RESET"
  printf '  %sreads your cloud, reports the exposure, changes nothing%s\n\n' "$C_DIM" "$C_RESET"
}

usage() {
  cat <<USAGE
Usage:
  ./raqib.sh [scan] [--cloud aws|azure|gcp|k8s] [--strict] [--json]
             scan the cloud you are signed in to, live, read only. This is the default.
  ./raqib.sh scan --offline EXPORT.json [--cloud CLOUD] [--strict] [--json]
             read a saved export instead of calling a cloud, for air gapped review.
  ./raqib.sh defends
             print the whole cloud by tactic map of what Raqib checks.

Notes:
  Live scanning needs jq and the CLI for the cloud you scan (aws, az, gcloud, kubectl),
  already signed in. Raqib only ever runs read only enumeration calls.
USAGE
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
  local forced_cloud="" offline="" strict=0 as_json=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --cloud) forced_cloud="$2"; shift 2 ;;
      --offline) offline="$2"; shift 2 ;;
      --strict) strict=1; shift ;;
      --json) as_json=1; shift ;;
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

  local c ep
  for c in "${targets[@]}"; do
    ep="$(export_path_for "$c")"
    [ -f "$ep" ] || continue
    analyze_cloud "$c" "$ep"
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

main() {
  local sub="${1:-scan}"
  case "$sub" in
    defends) cmd_defends ;;
    scan) shift || true; cmd_scan "$@" ;;
    -h|--help) banner; usage ;;
    --*) cmd_scan "$@" ;;
    *) log_error "unknown command: $sub"; usage; exit 2 ;;
  esac
}
main "$@"
