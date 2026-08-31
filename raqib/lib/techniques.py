"""Assign the MITRE ATT&CK technique each finding defends against, by its shape."""

def _technique_for(f):
    tactic = f.get("tactic")
    title = f.get("title", "")
    refs = " ".join(f.get("refs", []))
    if tactic == "defense evasion":
        return {"id": "T1562.008", "name": "Impair Defenses: Disable or Modify Cloud Logs"}
    if tactic == "lateral movement":
        return {"id": "T1199", "name": "Trusted Relationship"}
    if tactic == "reconnaissance":
        return {"id": "T1580", "name": "Cloud Infrastructure Discovery"}
    if tactic == "exfiltration":
        return {"id": "T1530", "name": "Data from Cloud Storage"}
    if tactic == "exposure":
        return {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"}
    if tactic == "persistence":
        return {"id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials"}
    # privilege escalation
    if "Administrator" in title or "service wildcard" in title:
        return {"id": "T1078.004", "name": "Valid Accounts: Cloud Accounts"}
    if "passrole" in refs:
        return {"id": "T1548", "name": "Abuse Elevation Control Mechanism"}
    if "create-access-key" in refs:
        return {"id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials"}
    if "login-profile" in refs:
        return {"id": "T1098", "name": "Account Manipulation"}
    return {"id": "T1098.003", "name": "Account Manipulation: Additional Cloud Roles"}


def apply_techniques(findings):
    for f in findings:
        f["technique"] = _technique_for(f)
    return findings
