"""Resumen de resultados del laboratorio (lee lab/results/)."""
import collections
import csv
import json
import os

R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results") + os.sep


def fmt(c):
    return ", ".join(f"{k}: {v}" for k, v in c.most_common())


def trivy(f):
    d = json.load(open(R + f))
    v = [x for r in d.get("Results", []) for x in (r.get("Vulnerabilities") or [])]
    return len(v), fmt(collections.Counter(x["Severity"] for x in v))


t = {r["herramienta"]: int(r["milisegundos"]) / 1000 for r in csv.DictReader(open(R + "tiempos.csv"))}
print("## Resultados del laboratorio")
print()
print("| Herramienta | Hallazgos | Detalle | Tiempo (s) |")
print("|---|---|---|---|")
g = json.load(open(R + "gitleaks.json"))
print(f"| Gitleaks | {len(g)} | {fmt(collections.Counter(x['RuleID'] for x in g))} | {t['gitleaks']:.1f} |")
s = json.load(open(R + "semgrep.json"))["results"]
print(f"| Semgrep | {len(s)} | {fmt(collections.Counter(x['extra']['severity'] for x in s))} | {t['semgrep']:.1f} |")
n, det = trivy("trivy-fs.json")
print(f"| Trivy (código) | {n} | {det} | {t['trivy-fs']:.1f} |")
n, det = trivy("trivy-image.json")
print(f"| Trivy (imagen) | {n} | {det} | {t['trivy-image']:.1f} |")
c = json.load(open(R + "sbom-image.cdx.json"))["components"]
lib = sum(1 for x in c if x["type"] == "library")
print(f"| Syft (SBOM) | {lib} | librerías, de {len(c)} entradas | {t['syft']:.1f} |")