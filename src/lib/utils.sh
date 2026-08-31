# Shared helpers: running jq against a gathered export, and collecting findings.
# Raqib is read only. The one guard here refuses to run anything that is not a
# read only enumeration call, so a wrong turn cannot change a cloud.

# every gather command is passed through this. it allows only the read verbs.
READONLY_ALLOW='^(aws|az|gcloud|kubectl)\b'
run_readonly() {
  # usage: run_readonly <cloud> <command...>   ; returns the command output
  local joined="$*"
  case "$1" in
    aws)
      case "$2 $3" in
        "iam get-account-authorization-details"*|"iam generate-credential-report"*|"iam get-credential-report"*) : ;;
        *) log_error "raqib: refusing a non read only aws call: $joined"; return 3 ;;
      esac ;;
    az)
      case "$2 $3 $4" in
        "role assignment list"*|"role definition list"*) : ;;
        *) log_error "raqib: refusing a non read only az call: $joined"; return 3 ;;
      esac ;;
    gcloud)
      case "$2 $3 $4" in
        "projects get-iam-policy"*) : ;;
        *) log_error "raqib: refusing a non read only gcloud call: $joined"; return 3 ;;
      esac ;;
    kubectl)
      case "$2" in
        get) : ;;
        *) log_error "raqib: refusing a non read only kubectl call: $joined"; return 3 ;;
      esac ;;
    *) log_error "raqib: unknown command: $joined"; return 3 ;;
  esac
  "$@"
}

# run a cloud analyzer module (jq) over a gathered export and append its findings.
# args: <cloud> <tactic> <path-to-export-json>  ; the jq filter is the tactic module.
analyze() {
  local cloud="$1" tactic="$2" json="$3"
  local module="$RAQIB_ROOT/src/modules/${tactic}_${cloud}.sh"
  [ -f "$module" ] || return 0
  # shellcheck disable=SC1090
  . "$module"
  local fn="analyze_${tactic}_${cloud}"
  declare -F "$fn" >/dev/null || return 0
  "$fn" "$json" 2>/dev/null | jq -c '.[]?' >> "$FINDINGS" 2>/dev/null || true
}

# helper the modules call: run jq with the cloud model on the path in the jq lib dir
jq_model() {
  # args: <cloud> <jq-filter> <json>
  jq -L "$RAQIB_ROOT/src/lib" -c "include \"model_$1\"; $2" "$3" 2>/dev/null
}

sev_rank() { case "$1" in critical) echo 0;; high) echo 1;; medium) echo 2;; low) echo 3;; *) echo 9;; esac; }
