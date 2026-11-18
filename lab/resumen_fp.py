#!/usr/bin/env python3
"""Calcula la precision a partir de docs/falsos-positivos/muestra.csv ya revisada.

Uso (desde la raiz del repositorio):
    python3 lab/resumen_fp.py
Escribe ademas docs/falsos-positivos/resumen-fp.md
"""
import argparse
import collections
import csv
import math
import os


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - m), min(1.0, c + m))


def pct(x):
    return f"{100 * x:.0f} %"


def leer(ruta):
    with open(ruta, encoding="utf-8-sig", newline="") as f:
        muestra = f.read(4096)
        f.seek(0)
        delim = max(";,\t", key=muestra.count)
        return list(csv.DictReader(f, delimiter=delim))


def main():
    aqui = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(os.path.dirname(aqui), "docs", "falsos-positivos", "muestra.csv"))
    a = ap.parse_args()
    filas = leer(a.csv)
    norm = {"VP": "VP", "TP": "VP", "FP": "FP", "ND": "ND"}

    est = collections.OrderedDict()
    pendientes = 0
    for f in filas:
        v = norm.get((f.get("veredicto") or "").strip().upper(), "")
        if not v:
            pendientes += 1
        clave = (f["herramienta"], f["estrato"])
        e = est.setdefault(clave, {"N": int(f["poblacion"]), "tipo": f["muestreo"], "VP": 0, "FP": 0, "ND": 0, "sin": 0, "filas": 0})
        e["filas"] += 1
        e[v or "sin"] += 1

    out = ["# Resumen de falsos positivos", ""]
    out += ["| Herramienta | Estrato | Revisados / total | Muestreo | VP | FP | ND | Sin revisar | Precision | IC 95 % (si aleatoria) |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    por_herr = collections.defaultdict(list)
    for (h, s), e in est.items():
        n = e["VP"] + e["FP"]
        prec = e["VP"] / n if n else None
        ic = ""
        if e["tipo"] == "aleatoria" and n:
            lo, hi = wilson(e["VP"], n)
            ic = f"{pct(lo)} – {pct(hi)}"
        out.append(f"| {h} | {s} | {e['filas']} / {e['N']} | {e['tipo']} | {e['VP']} | {e['FP']} | {e['ND']} | {e['sin']} | "
                   f"{pct(prec) if prec is not None else 's/d'} | {ic} |")
        if prec is not None:
            por_herr[h].append((e["N"], prec))
    out += ["", "## Precision por herramienta (ponderada por el tamano de cada estrato, solo sobre lo muestreado)", ""]
    out += ["| Herramienta | Precision ponderada | Alcance |", "|---|---|---|"]
    alcance = {"Gitleaks": "todos los hallazgos (3 reglas)", "Semgrep": "ERROR (censo) + resto (muestra)",
               "Trivy": "solo CRITICAL (codigo e imagen)"}
    for h, lst in por_herr.items():
        tot = sum(n for n, _ in lst)
        out.append(f"| {h} | {pct(sum(n * p for n, p in lst) / tot)} | {alcance.get(h, '')} |")
    out += ["", f"Filas sin revisar: {pendientes}. Los ND se excluyen del calculo."]
    texto = "\n".join(out) + "\n"
    print(texto)
    ruta = os.path.join(os.path.dirname(a.csv), "resumen-fp.md")
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(texto)
    print(f"Guardado en {ruta}")


if __name__ == "__main__":
    main()