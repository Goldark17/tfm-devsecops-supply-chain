"""Rellena veredicto y nota en muestra.csv y calcula la precisión por herramienta.

Uso: python3 -I veredictos.py muestra.csv muestra_veredictos.csv
"""
import csv
import math
import sys
from collections import defaultdict

V = {}

def put(ids, ver, nota):
    for i in ids:
        V[i] = (ver, nota)

# --- Gitleaks ---------------------------------------------------------------
put(["GL-01", "GL-02", "GL-03"], "VP",
    "Clave privada RSA real embebida en el código; la aplicación la usa para firmar los JWT "
    "(lib/insecurity.ts). Misma clave en 3 rutas: 1 hallazgo único.")
put(["GL-04"], "FP",
    "Dirección pública de un contrato (0x + 40 hex), no una clave.")
put(["GL-05", "GL-06"], "FP",
    "Fixture de test: base64 del email invertido de test@test.com. Ojo: refleja el esquema "
    "predecible de contraseñas OAuth de Juice Shop, que es el riesgo real y Gitleaks no detecta.")
put(["GL-07", "GL-08", "GL-09", "GL-10", "GL-11"], "FP",
    "Secreto TOTP de prueba generado para los tests de 2FA; no protege ninguna cuenta real.")
put(["GL-12"], "FP",
    "Secreto TOTP del usuario sembrado de pruebas, usado en un test; dato de demo, no secreto de producción.")
put(["GL-13", "GL-15", "GL-16", "GL-17", "GL-18", "GL-19", "GL-20", "GL-21", "GL-22", "GL-23"], "FP",
    "Contraseña del usuario sembrado en un test (base64 del email invertido). Credencial de "
    "fixture; el problema de fondo es el esquema derivable, no la fuga.")
put(["GL-14"], "FP",
    "Valor de 40 hex (formato de dirección, no de clave privada de 64 hex) enviado en un test.")
put(["GL-24"], "FP", "Token de ejemplo de jwt.io (John Doe) en un test de frontend.")
put(["GL-25"], "FP", "JWT de prueba con datos ficticios en un test de frontend.")
put(["GL-26", "GL-30", "GL-31"], "FP",
    "JWT RS256 de administrador en un test. Solo es explotable porque la clave privada está "
    "embebida (ya contado como VP en GL-01 a GL-03); el token en sí es un fixture.")
put(["GL-27", "GL-28", "GL-29", "GL-32", "GL-33", "GL-34", "GL-35"], "FP",
    "Token falsificado a propósito (alg none o firma inválida) para probar los retos de JWT; no es una credencial.")

# --- Semgrep ----------------------------------------------------------------
put(["SG-01"], "VP",
    "curl | sh en CI: si el servidor o la URL se comprometen, se ejecuta código arbitrario en el runner. "
    "Riesgo real de cadena de suministro.")
put(["SG-02", "SG-03", "SG-04", "SG-05", "SG-06"], "FP",
    "github.ref_name solo llega por push a master/develop o workflow_dispatch (requiere permiso de escritura); "
    "un atacante externo no lo controla. Comprobado en el workflow del commit fijado.")
put(["SG-07", "SG-08", "SG-09", "SG-10"], "FP",
    "FP por zona: fragmento didáctico en data/static/codefixes que se muestra como texto en el reto de "
    "código y no se ejecuta. El patrón sí es vulnerable (ver análisis de sensibilidad).")
put(["SG-11"], "VP", "Inyección SQL en el login (reto conocido de Juice Shop).")
put(["SG-12"], "VP", "Inyección SQL en la búsqueda (reto UNION SQL injection).")
put(["SG-13"], "VP", "eval() con datos del usuario en el perfil: ejecución de código (reto SSTI).")
put(["SG-14"], "FP",
    "FP por zona: fichero .tf didáctico en data/static/codefixes, no se despliega. "
    "Además el listener es HTTP, no TLS antiguo.")
put(["SG-15"], "FP",
    "Subred pública por diseño en el fichero de solución correcta (_correct.tf) de un reto; no es un error.")
put(["SG-16"], "VP",
    "El filtro de '/' impide salir de ftp/, pero el filtro de extensión se evita con byte nulo "
    "(reto Poison Null Byte): lectura de ficheros no autorizados.")
put(["SG-17"], "VP", "Expone los ficheros de log del servidor (reto Access Log).")
put(["SG-18"], "VP",
    "Hay lista de permitidos, pero comprueba con includes() y se puede evitar (reto Allowlist Bypass).")
put(["SG-19"], "VP", "Listado del directorio /encryptionkeys: expone claves.")
put(["SG-20"], "VP", "Listado del directorio /support/logs: expone logs de acceso.")

# --- Trivy ------------------------------------------------------------------
TRIVY = {
    "CVE-2023-46233": "crypto-js 3.3.0 < 4.2.0 (rango afectado).",
    "CVE-2026-71851": "crypto-js 3.3.0 < 4.0.0: PRNG débil en WordArray.random() (aviso GHSA-rg76-677x-56q9).",
    "CVE-2026-101894": "El aviso cubre también el paquete decompress sin mantenimiento hasta 4.2.1 "
                       "(no es confusión de nombre); sin versión corregida.",
    "CVE-2026-53486": "El aviso cubre decompress <= 4.2.1 además de @xhmikosr/decompress; sin versión corregida.",
    "CVE-2015-9235": "jsonwebtoken < 4.2.2 (rango afectado).",
    "CVE-2019-10744": "lodash < 4.17.12 (rango afectado).",
    "GHSA-5mrr-rgp6-x4gr": "marsdb sin versión corregida; Juice Shop lo usa para los retos NoSQL.",
    "CVE-2026-59873": "node-tar afectado hasta 7.5.18 inclusive; 6.2.1 está en el rango.",
    "CVE-2026-106445": "handlebars < 4.7.10. Explotable solo con plantilla controlada por el atacante y allowProtoMethodsByDefault.",
    "CVE-2026-106446": "handlebars < 4.7.10. Explotable solo si se pasa un AST pre-parseado a compile().",
}
DUP = "Mismo hallazgo en código e imagen: cuenta como 1 revisión única."


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"),) * 2
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return max(0.0, c - h), min(1.0, c + h)


def main(src, dst):
    with open(src, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f, delimiter=";"))
        fields = list(rows[0].keys())
    for x in rows:
        if x["herramienta"] == "Trivy":
            nota = "Versión dentro del rango afectado. " + TRIVY[x["regla"]]
            if x["estrato"] == "CRITICAL-codigo" or x["regla"] not in ("CVE-2026-106445", "CVE-2026-106446"):
                nota += " " + DUP
            else:
                nota += " Solo en la imagen: el lockfile generado resuelve otra versión."
            x["veredicto"], x["nota"] = "VP", nota + " Alcanzabilidad no analizada."
        else:
            x["veredicto"], x["nota"] = V[x["id"]]
    falta = [x["id"] for x in rows if not x["veredicto"]]
    assert not falta, falta
    with open(dst, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter=";", lineterminator="\r\n")
        w.writeheader()
        w.writerows(rows)

    print("Herramienta | VP | FP | ND | n | Precisión por fila | IC Wilson 95 % | Ponderada por estrato")
    for tool in ("Gitleaks", "Semgrep", "Trivy"):
        t = [x for x in rows if x["herramienta"] == tool]
        vp = sum(x["veredicto"] == "VP" for x in t)
        fp = sum(x["veredicto"] == "FP" for x in t)
        nd = sum(x["veredicto"] == "ND" for x in t)
        lo, hi = wilson(vp, vp + fp)
        est = defaultdict(list)
        for x in t:
            est[(x["estrato"], int(x["poblacion"]))].append(x["veredicto"])
        num = den = 0
        for (_, pob), vs in est.items():
            d = [v for v in vs if v != "ND"]
            if d:
                num += pob * sum(v == "VP" for v in d) / len(d)
                den += pob
        print(f"{tool} | {vp} | {fp} | {nd} | {len(t)} | {vp/(vp+fp):.1%} | {lo:.1%} – {hi:.1%} | {num/den:.1%}")

    # Sensibilidad: codefixes de Semgrep como VP
    cf = {"SG-07", "SG-08", "SG-09", "SG-10", "SG-14"}
    s = [x for x in rows if x["herramienta"] == "Semgrep"]
    vp = sum(x["veredicto"] == "VP" or x["id"] in cf for x in s)
    lo, hi = wilson(vp, len(s))
    print(f"Semgrep si codefixes = VP | {vp}/{len(s)} = {vp/len(s):.1%} | {lo:.1%} – {hi:.1%}")
    e = [x for x in s if x["estrato"] == "ERROR"]
    k = sum(x["veredicto"] == "VP" for x in e)
    print(f"Semgrep solo ERROR (censo 13) | {k}/13 = {k/13:.1%}; con codefixes VP: {k+4}/13 = {(k+4)/13:.1%}")
    # Gitleaks por valor único
    g = [x for x in rows if x["herramienta"] == "Gitleaks"]
    print("Gitleaks por estrato:", {e: sum(x['veredicto']=='VP' for x in g if x['estrato']==e) for e in ('private-key','generic-api-key','jwt')})


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
