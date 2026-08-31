# report.sh -- render the collected findings. Terminal by default, JSON on request.

technique_for() {
  case "$1" in
    "reconnaissance") echo "T1580 Cloud Infrastructure Discovery" ;;
    "privilege escalation") echo "T1098 Account Manipulation" ;;
    "persistence") echo "T1098 Account Manipulation" ;;
    "lateral movement") echo "T1199 Trusted Relationship" ;;
    "exfiltration") echo "T1530 Data from Cloud Storage" ;;
    "defense evasion") echo "T1562.008 Disable or Modify Cloud Logs" ;;
    "credential exposure") echo "T1078 Valid Accounts" ;;
    *) echo "" ;;
  esac
}

report_json() { jq -s '.' "$FINDINGS"; }

report_terminal() {
  local cloud="$1"
  local total crit high med low
  total=$(wc -l < "$FINDINGS" | tr -d ' ')
  crit=$(grep -c '"severity":"critical"' "$FINDINGS" 2>/dev/null || true)
  high=$(grep -c '"severity":"high"' "$FINDINGS" 2>/dev/null || true)
  med=$(grep -c '"severity":"medium"' "$FINDINGS" 2>/dev/null || true)
  low=$(grep -c '"severity":"low"' "$FINDINGS" 2>/dev/null || true)

  printf '\n  %s%s exposure report%s\n' "$C_BOLD" "$(echo "$cloud" | tr '[:lower:]' '[:upper:]')" "$C_RESET"
  printf '  %s%s findings   %s critical   %s high   %s medium   %s low%s\n\n' \
    "$C_DIM" "$total" "$crit" "$high" "$med" "$low" "$C_RESET"

  if [ "$total" -eq 0 ]; then
    printf '  %sNo findings. The export named nothing these rules look for.%s\n' "$C_GREEN" "$C_RESET"
    printf '  %sThat is not the same as secure. Raqib reads the paths it knows about.%s\n\n' "$C_DIM" "$C_RESET"
    return 0
  fi

  local sev color
  for sev in critical high medium low; do
    case "$sev" in critical) color=$C_MAG;; high) color=$C_RED;; medium) color=$C_YEL;; low) color=$C_CYAN;; esac
    jq -rc --arg s "$sev" 'select(.severity==$s)' "$FINDINGS" | while IFS= read -r line; do
      local title name kind tactic detail fix
      title=$(jq -r '.title' <<<"$line"); name=$(jq -r '.principal.name' <<<"$line")
      kind=$(jq -r '.principal.kind' <<<"$line"); tactic=$(jq -r '.tactic' <<<"$line")
      detail=$(jq -r '.detail' <<<"$line"); fix=$(jq -r '.fix' <<<"$line")
      printf '  %s%-8s%s %s%s%s  %s(%s %s)%s\n' "$color" "[$sev]" "$C_RESET" "$C_BOLD" "$title" "$C_RESET" "$C_DIM" "$kind" "$name" "$C_RESET"
      printf '           %s\n' "$detail"
      printf '           %sfix:%s %s\n' "$C_GREEN" "$C_RESET" "$fix"
      printf '           %s%s  |  %s%s\n\n' "$C_DIM" "$tactic" "$(technique_for "$tactic")" "$C_RESET"
    done
  done
}
