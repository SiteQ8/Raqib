"""Turn findings into something to read: a terminal report, a JSON document, or a
self contained HTML page. The HTML is one file with no assets, so it can be
attached to a ticket or opened anywhere.

The report is deliberately plain about what it is. A finding says what a permission
would allow. It is not proof the permission was used, and a clean report means the
export named nothing these rules look for, not that the account is secure.
"""

import html
import json

SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_TERMINAL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def _use_color(stream):
    try:
        return stream.isatty()
    except Exception:
        return False


COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[90m", "reset": "\033[0m", "dim": "\033[90m", "bold": "\033[1m"}


def terminal(findings, summary, meta, stream):
    color = _use_color(stream)

    def c(key, text):
        return (COLORS.get(key, "") + text + COLORS["reset"]) if color else text

    lines = []
    title = meta.get("title") or "IAM exposure report"
    lines.append(c("bold", title))
    lines.append("")
    if not findings:
        lines.append("  nothing to flag by the rules Raqib checks")
    else:
        for f in findings:
            who = ""
            if f.get("principal"):
                who = "  " + f["principal"]["kind"] + " " + f["principal"]["name"]
            lines.append("  " + c(f["severity"], SEV_TERMINAL[f["severity"]].ljust(9)) + f["title"] + who)
            lines.append("          " + f["detail"])
            lines.append(c("dim", "          fix: " + f["fix"]))
            lines.append("")
    cc = summary["counts"]
    lines.append("  " + ", ".join(str(cc[s]) + " " + s for s in SEV_ORDER))
    lines.append("  " + str(summary["principals_with_findings"]) + " of " + str(summary["principals"]) + " principals have a finding")
    lines.append("")
    lines.append(c("dim", "  A finding says what a permission would allow, not that it was used. A clean"))
    lines.append(c("dim", "  report means the export named nothing these rules look for."))
    stream.write("\n".join(lines) + "\n")


def as_json(findings, summary, meta):
    return json.dumps({
        "title": meta.get("title"),
        "source": meta.get("source"),
        "summary": summary,
        "findings": findings,
    }, indent=2)


_TACTIC_NOTE = {
    "privilege escalation": "a way to gain more permission than intended",
    "lateral movement": "a way to reach another principal or account",
    "reconnaissance": "broad visibility an attacker would use to plan",
    "persistence": "a way to keep access once gained",
    "exposure": "a credential or setting an attacker would exploit",
}


def html_report(findings, summary, meta):
    e = html.escape
    title = meta.get("title") or "IAM exposure report"
    cc = summary["counts"]
    sev_colors = {"critical": "#e5484d", "high": "#e5844b", "medium": "#d9a441", "low": "#8a94a6"}

    cards = "".join(
        f'<div class="stat"><div class="num" style="color:{sev_colors[s]}">{cc[s]}</div><div class="lbl">{s}</div></div>'
        for s in SEV_ORDER
    )

    rows = []
    if not findings:
        rows.append('<div class="clean">Nothing to flag by the rules Raqib checks. That means the export named nothing these rules look for, not that the account is secure.</div>')
    else:
        for f in findings:
            who = ""
            if f.get("principal"):
                who = f'<span class="who">{e(f["principal"]["kind"])} {e(f["principal"]["name"])}</span>'
            refs = ""
            if f.get("refs"):
                refs = '<div class="refs">' + " ".join(e(r) for r in f["refs"]) + "</div>"
            tactic = f.get("tactic", "")
            tnote = _TACTIC_NOTE.get(tactic, "")
            rows.append(
                f'<div class="finding" data-sev="{f["severity"]}">'
                f'<div class="bar" style="background:{sev_colors[f["severity"]]}"></div>'
                f'<div class="body">'
                f'<div class="head"><span class="sev" style="color:{sev_colors[f["severity"]]}">{f["severity"]}</span>'
                f'<span class="ttl">{e(f["title"])}</span>{who}</div>'
                f'<div class="detail">{e(f["detail"])}</div>'
                f'<div class="fix"><span class="fixlbl">fix</span> {e(f["fix"])}</div>'
                f'<div class="tactic">defends against: {e(tactic)}{(" &middot; " + e(tnote)) if tnote else ""}</div>'
                f'{refs}</div></div>'
            )

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title>
<meta name="generator" content="Raqib">
<style>
:root{{--bg:#0e1320;--panel:#161f31;--line:#26314a;--text:#e8edf6;--dim:#93a1ba;--accent:#4bd6c8}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:28px}}
.wrap{{max-width:900px;margin:0 auto}}
h1{{font-size:22px;margin:0 0 4px}}
.sub{{color:var(--dim);font-size:13px;margin-bottom:20px}}
.stats{{display:flex;gap:12px;margin-bottom:22px;flex-wrap:wrap}}
.stat{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 20px;min-width:96px;text-align:center}}
.num{{font-size:28px;font-weight:700;line-height:1}}
.lbl{{color:var(--dim);font-size:12px;margin-top:4px;text-transform:capitalize}}
.finding{{display:flex;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-bottom:12px}}
.bar{{width:5px;flex:none}}
.body{{padding:13px 16px;min-width:0}}
.head{{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}}
.sev{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-right:8px}}
.ttl{{font-weight:650;font-size:15px;margin-right:8px}}
.who{{color:var(--dim);font-size:12.5px;font-family:ui-monospace,Menlo,Consolas,monospace}}
.detail{{color:var(--text);opacity:.92;font-size:13.5px;margin-top:6px}}
.fix{{color:var(--dim);font-size:13px;margin-top:7px}}
.fixlbl{{color:var(--accent);font-weight:600;text-transform:uppercase;font-size:10.5px;letter-spacing:.5px;margin-right:4px}}
.tactic{{color:var(--dim);font-size:11.5px;margin-top:8px;opacity:.8}}
.refs{{color:var(--dim);font-size:11px;margin-top:4px;font-family:ui-monospace,Menlo,Consolas,monospace;opacity:.7}}
.clean{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;color:var(--dim)}}
.note{{color:var(--dim);font-size:12px;margin-top:22px;border-top:1px solid var(--line);padding-top:14px}}
.mark{{color:var(--accent);font-weight:600}}
</style></head>
<body><div class="wrap">
<h1>{e(title)}</h1>
<div class="sub">{e(str(summary["principals_with_findings"]))} of {e(str(summary["principals"]))} principals have a finding{(" &middot; from " + e(meta["source"])) if meta.get("source") else ""}</div>
<div class="stats">{cards}</div>
{"".join(rows)}
<div class="note">A finding says what a permission would allow, not that it was used. A clean report means the export named nothing these rules look for, not that the account is secure. Read only analysis by <span class="mark">Raqib</span>.</div>
</div></body></html>"""
