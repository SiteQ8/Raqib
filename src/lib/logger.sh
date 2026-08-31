# Logging helpers for Raqib. Colour when the terminal supports it, plain otherwise.
# Read only note: this file prints, it never changes anything.

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_MAG=$'\033[35m'
else
  C_RESET=; C_DIM=; C_BOLD=; C_RED=; C_YEL=; C_CYAN=; C_GREEN=; C_MAG=
fi

log_info()  { printf '%s\n' "${C_DIM}$*${C_RESET}" >&2; }
log_step()  { printf '%s\n' "${C_CYAN}$*${C_RESET}" >&2; }
log_warn()  { printf '%s\n' "${C_YEL}$*${C_RESET}" >&2; }
log_error() { printf '%s\n' "${C_RED}$*${C_RESET}" >&2; }
log_ok()    { printf '%s\n' "${C_GREEN}$*${C_RESET}" >&2; }
