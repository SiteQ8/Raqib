#!/usr/bin/env python3
"""Build docs/report.html, the interactive four cloud exposure explorer.

Runs the Raqib engine over every vulnerable sample, then renders one self contained
page: a summary, a cloud by tactic matrix, and every finding as a card that can be
filtered live by cloud, tactic, severity, and text. The findings are written into the
static HTML so the page reads with no script; the script only adds the filtering.

    python3 docs/build_explorer.py
"""
import html
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from raqib import audit  # noqa: E402

CLOUDS = [("aws", "AWS"), ("azure", "Azure"), ("gcp", "GCP"), ("k8s", "Kubernetes")]
TACTICS = [
    ("reconnaissance", "Reconnaissance"),
    ("privilege escalation", "Privilege escalation"),
    ("persistence", "Persistence"),
    ("lateral movement", "Lateral movement"),
    ("exfiltration", "Exfiltration"),
    ("defense evasion", "Defense evasion"),
]
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEV_LABELS = ["critical", "high", "medium", "low"]


def collect():
    findings = []
    per_cloud = {}
    for c, label in CLOUDS:
        with open(os.path.join(ROOT, "samples", c, "vulnerable.json")) as fh:
            export = json.load(fh)
        fs, summ, _ = audit(export, cloud=c)
        per_cloud[c] = {"label": label, "total": summ["total"], "counts": summ["counts"],
                        "principals": summ["principals"]}
        for f in fs:
            f = dict(f)
            f["cloud"] = c
            f["cloudLabel"] = label
            findings.append(f)
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9),
                                 [c for c, _ in CLOUDS].index(f["cloud"]),
                                 f["title"]))
    return findings, per_cloud


def esc(s):
    return html.escape(str(s or ""))


def technique_of(f):
    t = f.get("technique")
    if isinstance(t, dict):
        return (t.get("id", "") + " " + t.get("name", "")).strip()
    if t:
        return str(t)
    refs = f.get("refs") or []
    return refs[0] if refs else ""


def card_html(f):
    sev = f["severity"]
    p = f.get("principal") or {}
    who = ""
    if p.get("name"):
        who = esc((p.get("kind", "") + " " + p.get("name", "")).strip())
    tech = esc(technique_of(f))
    search = " ".join([f.get("title", ""), p.get("name", ""), p.get("kind", ""),
                       f.get("detail", ""), f.get("tactic", ""), f["cloudLabel"]]).lower()
    tech_span = ('<span class="tech">' + tech + "</span>") if tech else ""
    who_span = ('<span class="who">' + who + "</span>") if who else ""
    return (
        '<article class="finding" data-cloud="' + f["cloud"] + '" data-tactic="' + esc(f["tactic"])
        + '" data-sev="' + sev + '" data-search="' + esc(search) + '">'
        + '<span class="bar sev-' + sev + '"></span>'
        + '<div class="fbody">'
        + '<div class="fhead">'
        + '<span class="sevpill sev-' + sev + '">' + sev + "</span>"
        + '<span class="ftitle">' + esc(f.get("title", "")) + "</span>"
        + '<span class="cloudtag cloud-' + f["cloud"] + '">' + esc(f["cloudLabel"]) + "</span>"
        + who_span
        + "</div>"
        + '<p class="detail">' + esc(f.get("detail", "")) + "</p>"
        + '<p class="fix"><span class="fixlbl">fix</span>' + esc(f.get("fix", "")) + "</p>"
        + '<div class="tactic"><span class="tdot"></span>' + esc(f.get("tactic", "")) + tech_span + "</div>"
        + "</div></article>"
    )


def pill(group_val, label, count=None, pressed=False):
    c = (' <span class="pc">' + str(count) + "</span>") if count is not None else ""
    return ('<button type="button" class="pill" data-val="' + group_val + '" aria-pressed="'
            + ("true" if pressed else "false") + '">' + label + c + "</button>")


def stat(idkey, num, label, cls=""):
    return ('<div class="stat"><div class="num ' + cls + '" id="' + idkey + '">' + str(num)
            + '</div><div class="lbl">' + label + "</div></div>")


def matrix_html(findings, per_cloud):
    grid = {}
    for f in findings:
        grid.setdefault(f["cloud"], {}).setdefault(f["tactic"], 0)
        grid[f["cloud"]][f["tactic"]] += 1
    head = "".join('<th>' + short + "</th>" for _, short in
                   [(t, lab.split()[0]) for t, lab in TACTICS])
    rows = ""
    for c, label in CLOUDS:
        cells = ""
        for t, _ in TACTICS:
            n = grid.get(c, {}).get(t, 0)
            cls = "m-has" if n else "m-none"
            cells += '<td class="' + cls + '">' + (str(n) if n else "&middot;") + "</td>"
        total = per_cloud[c]["total"]
        rows += ('<tr><th class="mrow cloud-' + c + '">' + esc(label)
                 + ' <span class="mtot">' + str(total) + "</span></th>" + cells + "</tr>")
    return ('<table class="matrix"><thead><tr><th></th>' + head
            + "</tr></thead><tbody>" + rows + "</tbody></table>")


def read_version():
    with open(os.path.join(ROOT, "raqib", "__init__.py")) as fh:
        m = re.search(r'__version__\s*=\s*"([^"]+)"', fh.read())
    return m.group(1) if m else "0.0.0"


def to_index_finding(f):
    p = f.get("principal") or {}
    return {"severity": f["severity"], "title": f.get("title", ""),
            "principal": (p.get("name") or "the account"), "kind": (p.get("kind") or "account"),
            "detail": f.get("detail", ""), "fix": f.get("fix", ""), "tactic": f.get("tactic", "")}


def build_index_samples():
    out = {}
    for c, label in CLOUDS:
        with open(os.path.join(ROOT, "samples", c, "vulnerable.json")) as fh:
            vfindings, _, _ = audit(json.load(fh), cloud=c)
        with open(os.path.join(ROOT, "samples", c, "clean.json")) as fh:
            cfindings, _, _ = audit(json.load(fh), cloud=c)
        vfindings = sorted(vfindings, key=lambda f: SEV_ORDER.get(f["severity"], 9))
        out[c] = {"vulnerable": [to_index_finding(f) for f in vfindings],
                  "clean": [to_index_finding(f) for f in cfindings]}
    return out


def update_index():
    path = os.path.join(HERE, "index.html")
    if not os.path.exists(path):
        return
    s = open(path, encoding="utf-8").read()
    ver = read_version()

    samples = build_index_samples()
    s = re.sub(r"const SAMPLES = .*?;\n",
               "const SAMPLES = " + json.dumps(samples, ensure_ascii=False) + ";\n",
               s, count=1)

    s = re.sub(r"(<div class=\"badge\"><b></b>)v\d+\.\d+\.\d+", r"\g<1>v" + ver, s)
    s = re.sub(r"(read only cloud exposure auditor   )v\d+\.\d+\.\d+", r"\g<1>v" + ver, s)

    old_sub = ('<p class="s-sub">These are the findings Raqib produces on deliberately built example '
               'accounts, the same output the tool prints, rendered here. Switch the cloud, compare an '
               'exposed account with a clean one, and filter by severity.</p>')
    total = sum(len(v["vulnerable"]) for v in samples.values())
    new_sub = ('<p class="s-sub">These are the findings Raqib produces on deliberately built example '
               'accounts, the same output the tool prints. Switch the cloud, compare an exposed account '
               'with a clean one, and filter by severity. <a href="report.html" style="color:var(--accent);'
               'border-bottom:1px solid var(--accent)">Open the full report, all ' + str(total)
               + ' findings across four clouds &rarr;</a></p>')
    if old_sub in s:
        s = s.replace(old_sub, new_sub)

    open(path, "w", encoding="utf-8").write(s)
    print("updated", path, "(version v" + ver + ", refreshed sample findings)")


def build():
    findings, per_cloud = collect()
    total = len(findings)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_LABELS}
    tactic_counts = {t: sum(1 for f in findings if f["tactic"] == t) for t, _ in TACTICS}
    cloud_counts = {c: per_cloud[c]["total"] for c, _ in CLOUDS}

    stats = (stat("stat-total", total, "findings shown")
             + stat("stat-critical", counts["critical"], "critical", "sev-critical")
             + stat("stat-high", counts["high"], "high", "sev-high")
             + stat("stat-medium", counts["medium"], "medium", "sev-medium")
             + stat("stat-low", counts["low"], "low", "sev-low"))

    cloud_pills = pill("all", "All clouds", pressed=True)
    for c, label in CLOUDS:
        cloud_pills += pill(c, label, cloud_counts[c])
    tactic_pills = pill("all", "All tactics", pressed=True)
    for t, label in TACTICS:
        tactic_pills += pill(t, label, tactic_counts[t])
    sev_pills = pill("all", "All", pressed=True)
    for s in SEV_LABELS:
        sev_pills += pill(s, s[0].upper() + s[1:], counts[s])

    cards = "\n".join(card_html(f) for f in findings)
    matrix = matrix_html(findings, per_cloud)

    doc = TEMPLATE
    doc = doc.replace("__STATS__", stats)
    doc = doc.replace("__MATRIX__", matrix)
    doc = doc.replace("__CLOUD_PILLS__", cloud_pills)
    doc = doc.replace("__TACTIC_PILLS__", tactic_pills)
    doc = doc.replace("__SEV_PILLS__", sev_pills)
    doc = doc.replace("__CARDS__", cards)
    doc = doc.replace("__TOTAL__", str(total))
    doc = doc.replace("__NCLOUDS__", str(len(CLOUDS)))
    out = os.path.join(HERE, "report.html")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(doc)
    print("wrote", out, "with", total, "findings across", len(CLOUDS), "clouds")
    update_index()


TEMPLATE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Raqib &middot; Exposure across four clouds</title>
<meta name="description" content="An interactive read only exposure report across AWS, Azure, GCP, and Kubernetes. Filter __TOTAL__ findings by cloud, attacker tactic, and severity, each with the change that closes it.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06080c; --bg2:#0b0f18; --card:#0f1420; --card2:#131a29;
  --accent:#38bdf8; --accent-dim:#38bdf81a; --accent-mid:#38bdf855;
  --crit:#c084fc; --high:#ff4d67; --med:#fbbf24; --low:#38bdf8; --ok:#34d399;
  --aws:#ff9d3b; --azure:#5aa2ff; --gcp:#34d399; --k8s:#8b93ff;
  --text:#e8edf5; --dim:#8090ab; --faint:#4a5a76; --border:#1a2438; --border2:#26324a;
  --mono:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace; --sans:'Outfit',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.6;-webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;
  background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);
  background-size:52px 52px;opacity:.22;mask-image:radial-gradient(ellipse 90% 55% at 50% 0%,#000 20%,transparent 72%);-webkit-mask-image:radial-gradient(ellipse 90% 55% at 50% 0%,#000 20%,transparent 72%)}
a{color:inherit;text-decoration:none}
.wrap{max-width:1080px;margin:0 auto;padding:0 22px;position:relative;z-index:1}
.mono{font-family:var(--mono)}

nav{position:sticky;top:0;z-index:50;-webkit-backdrop-filter:blur(12px);backdrop-filter:blur(12px);background:rgba(6,8,12,.82);border-bottom:1px solid var(--border)}
.navrow{display:flex;align-items:center;justify-content:space-between;height:60px}
.logo{font-family:var(--mono);font-weight:700;font-size:18px;letter-spacing:1px}
.logo span{color:var(--accent)}
.navactions{display:flex;gap:10px;align-items:center}
.navlink{color:var(--dim);font-size:13.5px;font-weight:500;padding:7px 12px;border-radius:8px;transition:.15s}
.navlink:hover{color:var(--text);background:var(--card)}
.navgh{border:1px solid var(--border2);border-radius:8px;padding:7px 13px;font-size:13px;font-weight:600;transition:.15s}
.navgh:hover{border-color:var(--accent-mid);color:var(--accent)}

header.hero{padding:44px 0 18px}
.eyebrow{font-family:var(--mono);color:var(--accent);font-size:12.5px;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px}
h1{font-size:38px;line-height:1.12;font-weight:800;letter-spacing:-.5px;max-width:22ch}
.lede{color:var(--dim);font-size:16px;margin-top:14px;max-width:64ch}
.lede b{color:var(--text);font-weight:600}

.stats{display:flex;flex-wrap:wrap;gap:12px;margin-top:26px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:15px 20px;min-width:120px;flex:1 1 120px}
.num{font-size:30px;font-weight:800;line-height:1;font-family:var(--mono)}
.lbl{color:var(--dim);font-size:12.5px;margin-top:7px;text-transform:capitalize}

.section-h{display:flex;align-items:baseline;gap:12px;margin:34px 0 14px}
.section-h h2{font-size:15px;font-weight:700;letter-spacing:.3px}
.section-h .hint{color:var(--faint);font-size:12.5px}

.matrixwrap{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:6px 8px;overflow-x:auto}
table.matrix{border-collapse:collapse;width:100%;font-size:13px}
table.matrix th,table.matrix td{padding:11px 10px;text-align:center;white-space:nowrap}
table.matrix thead th{color:var(--dim);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid var(--border)}
table.matrix th.mrow{text-align:left;font-weight:700;font-family:var(--mono);font-size:13px}
.mtot{color:var(--bg);background:var(--dim);border-radius:20px;padding:1px 8px;font-size:11px;font-weight:700;margin-left:4px;font-family:var(--sans)}
td.m-has{color:var(--text);font-weight:700;font-family:var(--mono);background:var(--accent-dim)}
td.m-none{color:var(--faint)}
.cloud-aws{color:var(--aws)} .cloud-azure{color:var(--azure)} .cloud-gcp{color:var(--gcp)} .cloud-k8s{color:var(--k8s)}
th.mrow.cloud-aws .mtot{background:var(--aws)} th.mrow.cloud-azure .mtot{background:var(--azure)}
th.mrow.cloud-gcp .mtot{background:var(--gcp)} th.mrow.cloud-k8s .mtot{background:var(--k8s)}

.filters{position:sticky;top:60px;z-index:40;background:rgba(6,8,12,.9);-webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px);padding:14px 0 12px;margin-top:8px;border-bottom:1px solid var(--border)}
.searchbox{display:flex;align-items:center;gap:9px;background:var(--card);border:1px solid var(--border2);border-radius:11px;padding:9px 13px;margin-bottom:12px}
.searchbox svg{flex:none;opacity:.5}
#search{background:transparent;border:0;outline:0;color:var(--text);font-family:var(--sans);font-size:14.5px;width:100%}
#search::placeholder{color:var(--faint)}
.pillrow{display:flex;flex-wrap:wrap;gap:7px;align-items:center;margin-bottom:8px}
.pillrow .rl{color:var(--faint);font-size:11px;text-transform:uppercase;letter-spacing:.7px;font-weight:600;margin-right:4px;min-width:52px}
.pill{font-family:var(--sans);cursor:pointer;background:var(--card);color:var(--dim);border:1px solid var(--border2);border-radius:20px;padding:6px 13px;font-size:13px;font-weight:500;transition:.14s;display:inline-flex;align-items:center;gap:7px}
.pill:hover{color:var(--text);border-color:var(--faint)}
.pill .pc{background:var(--bg2);color:var(--dim);border-radius:20px;font-size:10.5px;font-weight:700;padding:1px 7px;font-family:var(--mono)}
.pill[aria-pressed="true"]{background:var(--accent-dim);border-color:var(--accent-mid);color:var(--accent)}
.pill[aria-pressed="true"] .pc{background:var(--accent);color:#04121c}
.showing{color:var(--dim);font-size:13px;margin:14px 2px 18px}
.showing b{color:var(--text);font-family:var(--mono)}

.list{padding-bottom:40px}
.finding{display:flex;background:var(--card);border:1px solid var(--border);border-radius:13px;overflow:hidden;margin-bottom:11px;transition:border-color .14s,transform .14s}
.finding:hover{border-color:var(--border2);transform:translateY(-1px)}
.bar{width:4px;flex:none}
.sev-critical{--s:var(--crit)} .sev-high{--s:var(--high)} .sev-medium{--s:var(--med)} .sev-low{--s:var(--low)}
.bar.sev-critical{background:var(--crit)} .bar.sev-high{background:var(--high)} .bar.sev-medium{background:var(--med)} .bar.sev-low{background:var(--low)}
.fbody{padding:14px 17px;min-width:0;flex:1}
.fhead{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.sevpill{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;padding:3px 9px;border-radius:20px;color:var(--s);border:1px solid var(--s);background:transparent;font-family:var(--mono)}
.ftitle{font-weight:600;font-size:15.5px;letter-spacing:-.1px}
.cloudtag{font-family:var(--mono);font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:6px;letter-spacing:.4px;background:var(--card2);border:1px solid var(--border2)}
.cloudtag.cloud-aws{color:var(--aws)} .cloudtag.cloud-azure{color:var(--azure)} .cloudtag.cloud-gcp{color:var(--gcp)} .cloudtag.cloud-k8s{color:var(--k8s)}
.who{color:var(--dim);font-size:12.5px;font-family:var(--mono);margin-left:auto}
.detail{color:var(--text);opacity:.9;font-size:14px;margin-top:9px}
.fix{color:var(--dim);font-size:13.5px;margin-top:8px}
.fixlbl{color:var(--ok);font-weight:700;text-transform:uppercase;font-size:10px;letter-spacing:.6px;margin-right:7px;font-family:var(--mono)}
.tactic{color:var(--faint);font-size:12px;margin-top:11px;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.tdot{width:5px;height:5px;border-radius:50%;background:var(--faint)}
.tech{color:var(--accent);font-family:var(--mono);font-size:11px;opacity:.85}
.empty{display:none;text-align:center;color:var(--dim);background:var(--card);border:1px dashed var(--border2);border-radius:14px;padding:44px 20px}
.empty b{color:var(--text)}

footer{border-top:1px solid var(--border);padding:26px 0 60px;margin-top:20px}
.foot{color:var(--faint);font-size:12.5px;max-width:75ch;line-height:1.7}
.foot b{color:var(--dim)}
.foot a{color:var(--accent)}

@media(max-width:720px){
  h1{font-size:29px} .num{font-size:24px} .stat{min-width:100px}
  .who{margin-left:0;width:100%} .navlink{display:none}
}
</style></head>
<body>
<nav><div class="wrap navrow">
  <a class="logo" href="./">RAQIB<span>_</span></a>
  <div class="navactions">
    <a class="navlink" href="./#tactics">Tactics</a>
    <a class="navlink" href="./#explore">Explore a scan</a>
    <a class="navgh" href="https://github.com/SiteQ8/Raqib">GitHub</a>
  </div>
</div></nav>

<header class="hero"><div class="wrap">
  <div class="eyebrow">Example exposure report</div>
  <h1>Exposure across four clouds, one lookout</h1>
  <p class="lede">Raqib read four example authorization exports and found <b>__TOTAL__ findings</b> across AWS, Azure, GCP, and Kubernetes, each the move an intruder would make after a foothold and the change that closes it. Filter by cloud, attacker tactic, and severity. Every reading is read only.</p>
  <div class="stats">__STATS__</div>
</div></header>

<div class="wrap">
  <div class="section-h"><h2>Findings by cloud and tactic</h2><span class="hint">the six tactics, read across every cloud</span></div>
  <div class="matrixwrap">__MATRIX__</div>
</div>

<div class="filters"><div class="wrap">
  <div class="searchbox">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"></circle><path d="M21 21l-4.3-4.3"></path></svg>
    <input id="search" type="text" placeholder="Search findings, principals, permissions..." autocomplete="off" spellcheck="false">
  </div>
  <div class="pillrow" id="f-cloud"><span class="rl">Cloud</span>__CLOUD_PILLS__</div>
  <div class="pillrow" id="f-tactic"><span class="rl">Tactic</span>__TACTIC_PILLS__</div>
  <div class="pillrow" id="f-sev"><span class="rl">Severity</span>__SEV_PILLS__</div>
</div></div>

<div class="wrap">
  <div class="showing">Showing <b id="shown-count">__TOTAL__</b> of __TOTAL__ findings</div>
  <div class="list" id="list">
__CARDS__
  </div>
  <div class="empty" id="empty">No findings match these filters. <b>Widen the selection</b> to see more.</div>
</div>

<footer><div class="wrap">
  <p class="foot">A finding says what a permission would allow, not that it was used. A clean report means the export named nothing these rules look for, not that the account is secure. These are example exports, not a live account. Raqib is <b>read only</b>: it reads who can do what and reports it, and never creates, changes, or deletes anything, or reads the contents of a secret, object, or key. Independent tool, not affiliated with or endorsed by any cloud provider. <a href="https://github.com/SiteQ8/Raqib">github.com/SiteQ8/Raqib</a></p>
</div></footer>

<script>
(function(){
  function qsa(sel,root){return Array.prototype.slice.call((root||document).querySelectorAll(sel));}
  function byId(id){return document.getElementById(id);}
  var state={cloud:"all",tactic:"all",sev:"all",q:""};
  var cards=qsa(".finding");
  function setText(id,v){var el=byId(id);if(el){el.textContent=v;}}
  function apply(){
    var shown=0, counts={critical:0,high:0,medium:0,low:0};
    for(var i=0;i<cards.length;i++){
      var c=cards[i];
      var ok=(state.cloud==="all"||c.getAttribute("data-cloud")===state.cloud)
        &&(state.tactic==="all"||c.getAttribute("data-tactic")===state.tactic)
        &&(state.sev==="all"||c.getAttribute("data-sev")===state.sev)
        &&(state.q===""||c.getAttribute("data-search").indexOf(state.q)!==-1);
      c.style.display=ok?"":"none";
      if(ok){shown++;counts[c.getAttribute("data-sev")]++;}
    }
    setText("shown-count",shown);
    setText("stat-total",shown);
    setText("stat-critical",counts.critical);
    setText("stat-high",counts.high);
    setText("stat-medium",counts.medium);
    setText("stat-low",counts.low);
    var empty=byId("empty"); if(empty){empty.style.display=shown===0?"block":"none";}
  }
  function wire(groupId,key){
    var btns=qsa("#"+groupId+" .pill");
    for(var i=0;i<btns.length;i++){
      (function(btn){
        btn.addEventListener("click",function(){
          state[key]=btn.getAttribute("data-val");
          for(var j=0;j<btns.length;j++){btns[j].setAttribute("aria-pressed", btns[j]===btn?"true":"false");}
          apply();
        });
      })(btns[i]);
    }
  }
  wire("f-cloud","cloud"); wire("f-tactic","tactic"); wire("f-sev","sev");
  var s=byId("search"); if(s){s.addEventListener("input",function(){state.q=s.value.toLowerCase();apply();});}
  apply();
})();
</script>
</body></html>
"""


if __name__ == "__main__":
    build()
