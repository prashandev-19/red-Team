"""CVSS v3.1 base score calculator + the 5 red team findings.   python cvss.py"""
import json
import math

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def score(vector):
    m = dict(part.split(":") for part in vector.split("/")[1:])
    changed = m["S"] == "C"
    pr = (PR_CHANGED if changed else PR_UNCHANGED)[m["PR"]]
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr * UI[m["UI"]]
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return roundup(min(total, 10))


def severity(s):
    return "None" if s == 0 else "Low" if s < 4 else "Medium" if s < 7 else "High" if s < 9 else "Critical"


# id, attack, CVSS vector, closest MITRE ATLAS technique
FINDINGS = [
    ("F1", "Indirect prompt injection (JWT exfiltration)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "AML.T0051.001"),
    ("F2", "Agent identity spoofing", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "AML.T0012"),
    ("F3", "System prompt extraction", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", "AML.T0056"),
    ("F4", "RAG chunk poisoning", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N", "AML.T0070"),
    ("F5", "MCP tool abuse via poisoned chunk", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:N", "AML.T0053"),
]

CATEGORY = {"F1": "Indirect prompt injection", "F2": "Agent identity spoofing", "F3": "System prompt extraction",
            "F4": "RAG poisoning", "F5": "MCP abuse"}


def measured():
    """Success counts per attack from results.json (created by: python run_attacks.py all)."""
    try:
        rows = json.load(open("results.json"))["results"]
    except (OSError, KeyError, ValueError):
        return {}
    out = {}
    for r in rows:
        if not r["error"]:
            c = out.setdefault(r["category"], [0, 0])
            c[0] += r["success"]
            c[1] += 1
    return out


if __name__ == "__main__":
    m = measured()
    print(f"{'ID':<4}{'Attack':<46}{'Score':>6}  {'Severity':<9}{'Worked':<8}{'ATLAS':<15}Vector")
    for fid, name, vec, atlas in sorted(FINDINGS, key=lambda f: -score(f[2])):
        s = score(vec)
        w = m.get(CATEGORY[fid])
        worked = f"{w[0]}/{w[1]}" if w else "-"
        print(f"{fid:<4}{name:<46}{s:>6}  {severity(s):<9}{worked:<8}{atlas:<15}{vec}")
    print("\nOpen a vector in the first.org calculator (screenshot 5):")
    for fid, name, vec, atlas in FINDINGS:
        print(f"{fid}: https://www.first.org/cvss/calculator/3.1#{vec}")
