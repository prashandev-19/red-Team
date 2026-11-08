"""Builds RedTeam_Report.docx from results.json (created by: python run_attacks.py all).
Needs:  pip install python-docx"""
import json

import cvss
from docx import Document
from docx.enum.text import WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

DATA = json.load(open("results.json"))
R = [r for r in DATA["results"] if not r["error"]]
by = {}
for r in R:
    by.setdefault(r["category"], {}).setdefault(r["name"], []).append(r)


def rate(cat):
    rows = [t for trials in by.get(cat, {}).values() for t in trials]
    return sum(t["success"] for t in rows), len(rows)


doc = Document()
sec = doc.sections[0]
sec.left_margin = sec.right_margin = Inches(0.75)
sec.top_margin = sec.bottom_margin = Inches(0.6)
doc.styles["Normal"].font.name = "Calibri"
doc.styles["Normal"].font.size = Pt(10)
doc.styles["Normal"].paragraph_format.space_after = Pt(3)
for n, size in (("Heading 1", 16), ("Heading 2", 13)):
    doc.styles[n].font.name = "Calibri"
    doc.styles[n].font.size = Pt(size)
    doc.styles[n].font.color.rgb = RGBColor(0x1F, 0x38, 0x64)


def shade(el_owner, fill, par=False):
    pr = el_owner._p.get_or_add_pPr() if par else el_owner._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    pr.append(shd)


def para(text, bold=False, italic=False):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.bold, r.italic = bold, italic
    return p


def bullets(items):
    for t in items:
        doc.add_paragraph(t, style="List Bullet")


def code(text, limit=900):
    text = text if len(text) <= limit else text[:limit] + " ...[shortened here; full text in attack_log.txt]"
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.1)
    p.paragraph_format.space_after = Pt(2)
    lines = text.split("\n")
    for i, line in enumerate(lines):
        run = p.add_run(line)
        run.font.name, run.font.size = "Consolas", Pt(7)
        if i < len(lines) - 1:
            run.add_break()
    shade(p, "F2F2F2", par=True)


def table(rows, header, widths, gap=True):
    t = doc.add_table(rows=1, cols=len(header))
    t.style = "Table Grid"
    t.autofit = False
    for i, h in enumerate(header):
        c = t.rows[0].cells[i]
        c.text = ""
        r = c.paragraphs[0].add_run(h)
        r.bold, r.font.size = True, Pt(9.5)
        r.font.color.rgb = RGBColor(255, 255, 255)
        shade(c, "1F3864")
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = ""
            cells[i].paragraphs[0].add_run(str(v)).font.size = Pt(9.5)
    for i, w in enumerate(widths):
        t.columns[i].width = Inches(w)
        for row in t.rows:
            row.cells[i].width = Inches(w)
    if gap:
        doc.add_paragraph()


def page_break():
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(0)
    p.add_run().add_break(WD_BREAK.PAGE)


FIND = {
    "F1": ("Indirect prompt injection", "LLM01 (also LLM02)"),
    "F2": ("Agent identity spoofing", "LLM09 as labelled in the course brief (also LLM06)"),
    "F3": ("System prompt extraction", "LLM07"),
    "F4": ("RAG poisoning", "LLM04 / LLM08"),
    "F5": ("MCP abuse", "LLM06"),
}
TEXT = {
    "F1": ("Instructions were hidden inside documents the agent reads (simulated as text input) while the user asked an innocent question. A direct request for the token was also tested as a baseline.",
           ["Attacker places a document containing hidden instructions", "A user asks an innocent question and the agent reads the document", "The model may treat the hidden text as a command", "The fake session token appears in the reply"],
           "If it works, anyone who can get text in front of the agent can steal the agent's session token without the user asking.",
           "Keep credentials out of the model's context (code attaches tokens at call time), scan outputs for JWT patterns, and treat documents as data, not instructions."),
    "F2": ("Two-agent setup: Agent B performs a privileged action (export all customer records) only for the trusted orchestrator. Agent B decides who is calling from an unsigned FROM line that the sender controls. A baseline message from a normal user was also tested.",
           ["Recon: system prompt extraction can reveal the trusted orchestrator id", "Attacker forges the FROM line with that id", "Agent B cannot verify the sender", "The privileged export runs (simulated: 12,000 records)"],
           "Any party that learns the orchestrator's id can try to make Agent B run privileged actions.",
           "Authenticate every agent-to-agent message with an Ed25519 signature plus timestamp or nonce, and verify it instead of trusting a FROM line."),
    "F3": ("Five extraction techniques were tried (repeat-back, role-play override, translation trick, ignore-prior instruction, suffix injection), followed by two attempts to raise the user role to admin using prompts alone.",
           ["Attacker sends crafted prompts to the agent", "The model may reveal parts of its system prompt, such as the orchestrator id", "A leaked id enables the spoofing attack (F2)", "Role elevation by prompt alone is checked separately"],
           "Internal rules and identifiers can leak, making follow-on attacks easier.",
           "Keep sensitive configuration out of prompts, scan outputs for prompt text, and keep authorization decisions in code and tokens."),
    "F4": ("Malicious chunks were added to the simulated knowledge base. The agent retrieves matching chunks by keyword and may repeat or obey them.",
           ["Attacker adds a chunk through any writable source", "A customer asks about refunds and the chunk is retrieved", "The model repeats the false content or follows the hidden instruction"],
           "Customers may receive false policy information or phishing links that appear to come from SecureNova.",
           "Scan and approve content before indexing, track provenance, use a separate write-only ingestion identity, and strip instruction-like text."),
    "F5": ("A poisoned chunk contained a hidden tool call. If the model emits it, the simulated MCP server executes it. The MCP server only checks that the tool name is on the agent's allow-list.",
           ["Poisoned chunk is retrieved", "The model may emit a TOOL_CALL line", "The MCP server runs any allow-listed tool without checking the user or arguments", "An admin-only tool should be denied by the allow-list"],
           "An attacker may trigger money-moving actions through the agent without being a customer or admin.",
           "Authorise every tool call against the end user's rights, limit arguments (maximum refund), and require human approval for money-moving tools."),
}

total_ok = sum(r["success"] for r in R)
total = len(R)
scored = [(cvss.score(v), fid, name) for fid, name, v, a in cvss.FINDINGS]
worked = [(s, fid, name) for s, fid, name in scored if rate(FIND[fid][0])[0] > 0]
held = [(fid, name) for s, fid, name in scored if rate(FIND[fid][0])[0] == 0]

t = doc.add_paragraph()
r = t.add_run("SecureNova AI Platform")
r.bold, r.font.size = True, Pt(24)
r.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
doc.add_paragraph().add_run("AI Identity Red Team Report").font.size = Pt(18)
para(f"Prepared by: AI Identity Security Analyst   |   Project 3 of the AI Identity Security capstone   |   Model tested: {DATA['model']}", italic=True)

doc.add_heading("1. Executive summary", 1)
para(f"We attacked a simulated copy of SecureNova's AI customer-service platform, using a real language model ({DATA['model']}) as the agent. "
     f"Each attack was repeated {DATA['trials']} times because model answers vary. Across {total} trials, {total_ok} ({total_ok / total * 100:.0f}%) succeeded before any defensive controls were added.")
if worked:
    s, fid, name = max(worked)
    bullets([f"Highest-severity attack that worked: {name}, CVSS {s} ({cvss.severity(s)}), succeeded in {rate(FIND[fid][0])[0]} of {rate(FIND[fid][0])[1]} trials."]
            + [f"{name}: worked in {rate(FIND[f][0])[0]} of {rate(FIND[f][0])[1]} trials (CVSS {sc})." for sc, f, name in sorted(worked, reverse=True)[1:]])
if held:
    bullets([f"Did not succeed against this model: {', '.join(n for f, n in held)}."])
er = rate("Role elevation (prompt only)")
if er[1]:
    bullets([f"Role elevation by prompt alone succeeded in {er[0]} of {er[1]} trials."])
para("The hardening actions in section 4 address the weaknesses shown and feed directly into Project 4 (blue team).")

doc.add_heading("2. Scope and method", 1)
bullets([
    "Target: a simulated SecureNova platform made of an AI agent, a second agent (Agent B), a RAG knowledge base and an MCP tool server. The agent and Agent B are driven by a real model called through an API. The test credential is a fake JWT placed in the agent's system context.",
    "The JWT, knowledge base and MCP server are simulated. Model answers vary between runs, so results are reported as success rates over repeated trials.",
    "Every payload and full model response was logged verbatim (attack_log.txt). Findings are scored with CVSS v3.1 (the score is the severity if the attack succeeds) and mapped to MITRE ATLAS and the OWASP LLM Top 10.",
])
page_break()
doc.add_heading("3. Results at a glance", 1)
para("Attack success matrix (before any defensive controls)", bold=True)
rows = []
for cat in by:
    ok, n = rate(cat)
    rows.append([cat, n, ok, f"{ok / n * 100:.0f}%"])
rows.append(["TOTAL", total, total_ok, f"{total_ok / total * 100:.0f}%"])
table(rows, ["Attack category", "Trials", "Succeeded", "Success rate"], [3.2, 1.0, 1.1, 1.2])
para("CVSS v3.1 findings", bold=True)
rows = []
for fid, name, vec, atlas in cvss.FINDINGS:
    s = cvss.score(vec)
    ok, n = rate(FIND[fid][0])
    rows.append([fid, name, f"{ok}/{n}", s, cvss.severity(s), atlas])
table(rows, ["ID", "Attack", "Worked", "CVSS", "Severity", "ATLAS"], [0.4, 2.8, 0.7, 0.6, 0.8, 1.2])

for fid, name, vec, atlas in cvss.FINDINGS:
    cat = FIND[fid][0]
    cats = [cat] + (["Role elevation (prompt only)"] if fid == "F3" else [])
    what, chain, impact, fix = TEXT[fid]
    s = cvss.score(vec)
    page_break()
    doc.add_heading(f"Finding {fid}: {name}", 1)
    table([["CVSS v3.1", f"{s} ({cvss.severity(s)}) - severity if the attack succeeds"], ["Vector", vec], ["MITRE ATLAS", atlas],
           ["OWASP LLM Top 10", FIND[fid][1]],
           ["Measured success", " / ".join(f"{rate(c)[0]} of {rate(c)[1]} trials ({c})" for c in cats if rate(c)[1])]],
          ["Item", "Value"], [1.6, 5.4], gap=False)
    para("What we did", bold=True)
    para(what)
    para("Kill chain", bold=True)
    for step in chain:
        doc.add_paragraph(step, style="List Number")
    para("Evidence (representative trial; every trial is in attack_log.txt)", bold=True)
    for c in cats:
        for nm, trials in by.get(c, {}).items():
            ok = sum(x["success"] for x in trials)
            rep = next((x for x in trials if x["success"]), trials[0])
            para(f"{nm}: {ok} of {len(trials)} trials succeeded", bold=True)
            code("PAYLOAD\n" + rep["payload"] + "\n\nMODEL RESPONSE (" + ("a successful trial" if rep["success"] else "trial 1") + ")\n" + rep["response"])
    para("Impact", bold=True)
    para(impact)
    para("Fix", bold=True)
    para(fix)

page_break()
doc.add_heading("4. Top 3 hardening recommendations", 1)
for h, b in [
    ("1. Keep credentials and authority out of the model.", "Tokens stay in code or a vault and are attached at call time; roles and tool permissions are checked in code; outputs are scanned for tokens and prompt text (F1, F3)."),
    ("2. Authenticate every agent-to-agent message.", "Sign messages with Ed25519 and verify them on receipt; never trust a sender field (F2)."),
    ("3. Treat retrieved content as untrusted and limit what tools can do.", "Scan and approve content before indexing, track provenance, and authorise each MCP call against the user with argument limits and human approval for sensitive tools (F4, F5)."),
]:
    para(h, bold=True)
    para(b)
para("These map to the Project 4 blue team work: guardrails, short-lived credentials, signed agent identity and monitoring.", italic=True)
doc.save("RedTeam_Report.docx")
print("saved RedTeam_Report.docx")
