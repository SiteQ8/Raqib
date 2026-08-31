"""Compatibility shim. The checks now live in raqib.checks, organized by tactic to
mirror S7aba's modules. This module re exports them so existing imports keep working.
"""

from raqib.checks import (
    run, summarize, apply_techniques,
    PRIVESC_METHODS, TAMPER_GROUPS,
    check_reconnaissance, check_privilege_escalation, check_wildcards,
    check_persistence, check_trust, check_exfiltration, check_log_tampering,
    _technique_for, _finding, _principal_label, _account_id, _as_list,
    _wild_services, _boundary_note, _lower,
)
