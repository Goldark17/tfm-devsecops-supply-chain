#!/usr/bin/env python3
"""Muestreo reproducible de hallazgos para revisar falsos positivos.

Uso (desde la raiz del repositorio):
    python3 lab/muestreo_fp.py

Lee los informes de lab/results/, copia una instantanea a docs/falsos-positivos/informes/,
elige los hallazgos a revisar (censo o muestra aleatoria con semilla fija) y escribe:
    docs/falsos-positivos/muestra.csv        <- la hoja que hay que rellenar
    docs/falsos-positivos/zonas-semgrep.md   <- hallazgos de Semgrep por zona del repo
    docs/falsos-positivos/manifiesto.txt     <- semilla, commit, huellas SHA-256
    docs/falsos-positivos/CRITERIOS.md       <- criterios de revision
"""
import argparse
import collections
import csv
import datetime
import hashlib
import json
import os
import random
import shutil

# ---------------------------------------------------------------- configuracion
SEMILLA = 20261126            # fija: con los mismos informes sale siempre la misma muestra
GITLEAKS_MUESTRA = 20         # si una regla tiene mas de UMBRAL_CENSO hallazgos, se muestrean tantos
UMBRAL_CENSO = 15             # si tiene UMBRAL_CENSO o menos, se revisan todos
SEMGREP_RESTO_MUESTRA = 7     # ademas de TODOS los ERROR, se muestrean tantos de los demas
INFORMES = ["gitleaks.json", "semgrep.json", "trivy-fs.json", "trivy-image.json"]
# ----------------------------------------------------------------------------


def leer_env(ruta):
    d = {}
    try:
        for ln in open(ruta, encoding="utf-8"):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                d[k.strip()] = v.strip()
    except OSError:
        pass
    return d


def sha256(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(1 << 20), b""):
            h.update(bloque)
    return h.hexdigest()


def limpiar(t, n=200):
    t = " ".join(str(t or "").split())
    return t if len(t) <= n else t[: n - 1] + "…"


def ruta_relativa(p, objetivo):
    """Quita el prefijo del contenedor (/path/ o /src/) y devuelve (ruta relativa, existe)."""
    p0 = (p or "").replace("\\", "/")
    candidatas = []
    for pref in ("/path/", "/src/", "path/", "src/", "./"):
        if p0.startswith(pref):
            candidatas.append(p0[len(pref):])
    candidatas.append(p0.lstrip("/"))
    for c in candidatas:
        if os.path.isfile(os.path.join(objetivo, c)):
            return c, True
    return (candidatas[0] if candidatas else p0), False


def lineas(objetivo, rel, ini, fin=None, maximo=3):
    try:
        with open(os.path.join(objetivo, rel), encoding="utf-8", errors="replace") as f:
            todas = f.read().splitlines()
    except OSError:
        return "(fichero no encontrado en el objetivo)"
    fin = fin or ini
    trozo = todas[max(ini - 1, 0): min(fin, ini - 1 + maximo)]
    return limpiar(" ⏎ ".join(x.strip() for x in trozo), 220)


def zona(rel):
    r = rel.lower()
    nombre = r.rsplit("/", 1)[-1]
    if r.startswith(".github/") or ".gitlab-ci" in r or "/workflows/" in r:
        return "ci"
    if (r.endswith(".tf") or "terraform" in r or r.startswith("deploy/") or "vagrant" in r
            or "ansible" in r or nombre.startswith("dockerfile") or nombre.startswith("docker-compose")
            or "helm" in r or "k8s" in r or ".devcontainer" in r or ".gitpod" in r):
        return "iac/despliegue"
    if r.startswith("test/") or "/test/" in r or ".spec." in nombre or "cypress" in r or "e2e" in r:
        return "tests"
    if r.startswith("data/") or "/data/" in r:
        return "datos"
    if (r.startswith(("routes/", "lib/", "models/", "frontend/src/", "views/", "config/", "rsn/"))
            or nombre in ("server.ts", "app.ts", "server.js", "app.js")):
        return "aplicacion"
    return "otros"


def enlace_codigo(commit, rel, linea):
    if not commit:
        return ""
    return f"https://github.com/juice-shop/juice-shop/blob/{commit}/{rel}#L{linea}"


def muestrear(rng, items, k):
    items = sorted(items, key=lambda x: x["_clave"])
    if len(items) <= k:
        return items, "censo"
    return sorted(rng.sample(items, k), key=lambda x: x["_clave"]), "aleatoria"


def main():
    aqui = os.path.dirname(os.path.abspath(__file__))
    raiz = os.path.dirname(aqui)
    ap = argparse.ArgumentParser()
    ap.add_argument("--informes", default=os.path.join(raiz, "lab", "results"))
    ap.add_argument("--objetivo", default=os.path.join(raiz, "lab", "target", "juice-shop"))
    ap.add_argument("--salida", default=os.path.join(raiz, "docs", "falsos-positivos"))
    ap.add_argument("--semilla", type=int, default=SEMILLA)
    ap.add_argument("--nueva-instantanea", action="store_true",
                    help="vuelve a copiar los informes de lab/results (cambia los datos de partida)")
    ap.add_argument("--forzar", action="store_true",
                    help="regenera muestra.csv aunque ya tenga veredictos (BORRA lo anotado)")
    a = ap.parse_args()

    commit = leer_env(os.path.join(aqui, ".env")).get("JUICE_SHOP_COMMIT", "")
    os.makedirs(os.path.join(a.salida, "informes"), exist_ok=True)
    ruta_csv = os.path.join(a.salida, "muestra.csv")
    if os.path.exists(ruta_csv) and not a.forzar:
        with open(ruta_csv, encoding="utf-8-sig", newline="") as fh:
            ya = sum(1 for r in csv.DictReader(fh, delimiter=";") if (r.get("veredicto") or "").strip())
        if ya:
            raise SystemExit(f"muestra.csv ya tiene {ya} veredictos anotados; no se toca. "
                             "Usa --forzar solo si quieres EMPEZAR DE CERO (borra lo anotado).")

    # 1) instantanea de los informes (el analisis no debe cambiar si Trivy actualiza su BD)
    datos = {}
    usados = []
    for f in INFORMES:
        origen = os.path.join(a.informes, f)
        if not os.path.isfile(origen):
            raise SystemExit(f"Falta {origen}. Ejecuta antes: bash lab/run-all.sh")
        destino = os.path.join(a.salida, "informes", f)
        if os.path.exists(destino) and not a.nueva_instantanea:
            usados.append(f)
        elif os.path.abspath(origen) != os.path.abspath(destino):
            shutil.copy2(origen, destino)
        datos[f] = json.load(open(destino, encoding="utf-8"))
    if usados:
        print("Usando la INSTANTANEA ya guardada en docs/falsos-positivos/informes/ "
              "(no se sobrescribe con lab/results).")

    gl = datos["gitleaks.json"]
    sg = datos["semgrep.json"]["results"]

    def trivy_crit(nombre, ambito):
        out = []
        for r in datos[nombre].get("Results", []):
            for v in r.get("Vulnerabilities") or []:
                if v.get("Severity") == "CRITICAL":
                    out.append({"r": r, "v": v, "ambito": ambito,
                                "_clave": (v.get("VulnerabilityID", ""), v.get("PkgName", ""),
                                           v.get("InstalledVersion", ""), r.get("Target", ""))})
        return out

    def total_trivy(nombre):
        return sum(len(r.get("Vulnerabilities") or []) for r in datos[nombre].get("Results", []))

    print("Informes leidos:")
    print(f"  Gitleaks {len(gl)} | Semgrep {len(sg)} | Trivy codigo {total_trivy('trivy-fs.json')} "
          f"| Trivy imagen {total_trivy('trivy-image.json')}")
    print("  (referencia 10 nov: 69 / 43 / 68 / 129)")

    rng = random.Random(a.semilla)
    filas = []

    # ---------------------------------------------------------------- Gitleaks
    por_regla = collections.defaultdict(list)
    for x in gl:
        rel, ok = ruta_relativa(x.get("File", ""), a.objetivo)
        x["_rel"] = rel
        x["_clave"] = (rel, x.get("StartLine", 0), x.get("RuleID", ""))
        por_regla[x.get("RuleID", "?")].append(x)
    for regla in sorted(por_regla):
        elegidos, tipo = muestrear(rng, por_regla[regla], GITLEAKS_MUESTRA if len(por_regla[regla]) > UMBRAL_CENSO else UMBRAL_CENSO)
        for x in elegidos:
            rel, ln = x["_rel"], x.get("StartLine", 0)
            filas.append({
                "prioridad": 1 if regla == "private-key" else 2, "herramienta": "Gitleaks", "ambito": "codigo",
                "estrato": regla, "poblacion": len(por_regla[regla]), "muestreo": tipo,
                "regla": regla, "severidad": "", "zona": zona(rel), "ubicacion": f"{rel}:{ln}",
                "enlace": enlace_codigo(commit, rel, ln), "descripcion": limpiar(x.get("Description")),
                "contexto": lineas(a.objetivo, rel, ln, x.get("EndLine")),
            })

    # ---------------------------------------------------------------- Semgrep
    for x in sg:
        rel, ok = ruta_relativa(x.get("path", ""), a.objetivo)
        x["_rel"] = rel
        x["_clave"] = (rel, x["start"]["line"], x.get("check_id", ""))
    errores = [x for x in sg if x["extra"].get("severity") == "ERROR"]
    resto = [x for x in sg if x["extra"].get("severity") != "ERROR"]
    for estrato, grupo, k, prio in (("ERROR", errores, len(errores) or 1, 1),
                                    ("resto", resto, SEMGREP_RESTO_MUESTRA, 2)):
        elegidos, tipo = muestrear(rng, grupo, k)
        for x in elegidos:
            rel, ln = x["_rel"], x["start"]["line"]
            filas.append({
                "prioridad": prio, "herramienta": "Semgrep", "ambito": "codigo",
                "estrato": estrato, "poblacion": len(grupo), "muestreo": tipo,
                "regla": x.get("check_id", "").split(".")[-1], "severidad": x["extra"].get("severity", ""),
                "zona": zona(rel), "ubicacion": f"{rel}:{ln}", "enlace": enlace_codigo(commit, rel, ln),
                "descripcion": limpiar(x["extra"].get("message")),
                "contexto": lineas(a.objetivo, rel, ln, x["end"]["line"]),
            })

    # ---------------------------------------------------------------- Trivy (CRITICAL, censo)
    for nombre, ambito in (("trivy-fs.json", "codigo"), ("trivy-image.json", "imagen")):
        crit = trivy_crit(nombre, ambito)
        elegidos, tipo = muestrear(rng, crit, len(crit) or 1)
        for x in elegidos:
            v, r = x["v"], x["r"]
            vid = v.get("VulnerabilityID", "")
            filas.append({
                "prioridad": 1, "herramienta": "Trivy", "ambito": ambito,
                "estrato": f"CRITICAL-{ambito}", "poblacion": len(crit), "muestreo": tipo,
                "regla": vid, "severidad": "CRITICAL", "zona": "n/a",
                "ubicacion": f"{v.get('PkgName', '')}@{v.get('InstalledVersion', '')} ({r.get('Target', '')})",
                "enlace": v.get("PrimaryURL") or f"https://nvd.nist.gov/vuln/detail/{vid}",
                "descripcion": limpiar(v.get("Title") or v.get("Description")),
                "contexto": limpiar(f"corregida en: {v.get('FixedVersion') or 'sin version corregida'}"
                                    f" | estado: {v.get('Status', '')}"),
            })

    filas.sort(key=lambda f: (f["prioridad"], f["herramienta"], f["estrato"], f["ubicacion"]))
    cont = collections.Counter()
    for f in filas:
        pref = {"Gitleaks": "GL", "Semgrep": "SG", "Trivy": "TV"}[f["herramienta"]]
        cont[pref] += 1
        f["id"] = f"{pref}-{cont[pref]:02d}"
        f["veredicto"] = ""
        f["nota"] = ""

    cols = ["id", "prioridad", "herramienta", "ambito", "estrato", "poblacion", "muestreo", "regla",
            "severidad", "zona", "ubicacion", "enlace", "descripcion", "contexto", "veredicto", "nota"]
    with open(ruta_csv, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, delimiter=";")
        w.writeheader()
        w.writerows(filas)

    # ---------------------------------------------------------------- zonas de Semgrep (los 43)
    z = collections.defaultdict(collections.Counter)
    reglas = collections.defaultdict(collections.Counter)
    for x in sg:
        zn = zona(x["_rel"])
        z[zn][x["extra"].get("severity", "?")] += 1
        reglas[zn][x.get("check_id", "").split(".")[-1]] += 1
    with open(os.path.join(a.salida, "zonas-semgrep.md"), "w", encoding="utf-8") as f:
        f.write(f"# Hallazgos de Semgrep por zona del repositorio ({len(sg)} en total)\n\n")
        f.write("Zona asignada por heuristica sobre la ruta; hay que comprobar los casos dudosos.\n\n")
        f.write("| Zona | Hallazgos | Detalle por severidad | Reglas mas frecuentes |\n|---|---|---|---|\n")
        for zn in sorted(z, key=lambda k: -sum(z[k].values())):
            sev = ", ".join(f"{k} {v}" for k, v in z[zn].most_common())
            rg = ", ".join(f"{k} ({v})" for k, v in reglas[zn].most_common(3))
            f.write(f"| {zn} | {sum(z[zn].values())} | {sev} | {rg} |\n")
    print("\nSemgrep por zona:")
    for zn in sorted(z, key=lambda k: -sum(z[k].values())):
        print(f"  {zn:16} {sum(z[zn].values()):3}  {dict(z[zn])}")

    # ---------------------------------------------------------------- manifiesto y criterios
    with open(os.path.join(a.salida, "manifiesto.txt"), "w", encoding="utf-8") as f:
        f.write(f"fecha de generacion (UTC): {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M}\n")
        f.write(f"semilla: {a.semilla}\ncommit del objetivo: {commit}\n")
        f.write(f"gitleaks: umbral censo {UMBRAL_CENSO}, muestra {GITLEAKS_MUESTRA}; "
                f"semgrep: todos los ERROR + {SEMGREP_RESTO_MUESTRA} del resto; trivy: todos los CRITICAL\n\n")
        for nom in INFORMES:
            ruta = os.path.join(a.salida, "informes", nom)
            f.write(f"{sha256(ruta)}  {nom}\n")
    with open(os.path.join(a.salida, "CRITERIOS.md"), "w", encoding="utf-8") as f:
        f.write(CRITERIOS)

    print(f"\nFilas a revisar: {len(filas)}  (prioridad 1: {sum(1 for x in filas if x['prioridad'] == 1)}, "
          f"prioridad 2: {sum(1 for x in filas if x['prioridad'] == 2)})")
    por = collections.Counter((x["herramienta"], x["estrato"], x["muestreo"], x["poblacion"]) for x in filas)
    for (h, e, t, n), c in sorted(por.items()):
        print(f"  {h:9} {e:18} {t:9} {c:3} de {n}")
    print(f"\nHoja para rellenar: {ruta_csv}")


CRITERIOS = """# Criterios de revision de falsos positivos

Definidos **antes** de revisar, para que el criterio no cambie segun el resultado.

## Veredictos (columna `veredicto`)
- **VP** (verdadero positivo): el hallazgo es correcto. El secreto, la debilidad o la vulnerabilidad
  existe y aplica a lo escaneado. En Juice Shop muchos son intencionados (es una app vulnerable a proposito);
  siguen siendo VP porque la herramienta ha detectado algo real.
- **FP** (falso positivo): el hallazgo es incorrecto. No es un secreto (dato de ejemplo, hash, identificador),
  el patron de codigo no es vulnerable en su contexto, o la version instalada queda fuera del rango afectado.
- **ND** (no determinado): no se puede decidir con un esfuerzo razonable (maximo 5 minutos por hallazgo).

Cualquier otro valor en la columna se ignora. Escribir solo VP, FP o ND.

## Como decidir, por herramienta
- **Gitleaks:** abrir el enlace o mirar `contexto`. Pregunta: la cadena es una credencial/clave/token funcional
  o con pinta de serlo (no un texto de ejemplo, un hash de test o un identificador)? Una clave de pruebas
  con formato real cuenta como VP; un identificador o dato aleatorio que no da acceso a nada, FP.
- **Semgrep:** leer la regla (`descripcion`) y el codigo (`contexto`/enlace). Pregunta: el codigo es de verdad
  vulnerable en ese contexto? Si el dato no llega del usuario, o hay una validacion previa, es FP. Anotar la zona.
- **Trivy (CRITICAL):** abrir el enlace de la vulnerabilidad. Pregunta: la version instalada esta en el rango
  afectado? Si lo esta, es VP aunque no se pueda explotar en este contexto (anotarlo en `nota`). Si el aviso no
  aplica a esa version o a ese componente, FP.

## Precision
`precision = VP / (VP + FP)`. Los ND se excluyen y se reportan aparte. En las reglas con muestra aleatoria
se da un intervalo de confianza de Wilson al 95 %. Los CRITICAL de Trivy y los ERROR de Semgrep se revisan
todos (censo): ahi la precision es exacta, no estimada.
"""

if __name__ == "__main__":
    main()