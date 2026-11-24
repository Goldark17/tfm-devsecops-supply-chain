# Pipeline DevSecOps para la seguridad de la cadena de suministro de software

Trabajo Fin de Máster — Máster en Ciberseguridad (UCM).

Pipeline de CI/CD en GitHub Actions que analiza una aplicación con cuatro herramientas de seguridad de la cadena de suministro y bloquea el despliegue según una política configurable. Todo el laboratorio está definido en Docker Compose, así que se ejecuta igual en local y en GitHub Actions.

| Control | Herramienta | Qué detecta |
| --- | --- | --- |
| Secretos | Gitleaks 8.30.1 | Claves, tokens y credenciales en el código |
| SAST | Semgrep 1.182.1 | Patrones de código inseguro |
| Dependencias e imagen | Trivy 0.76.1 | Componentes con vulnerabilidades conocidas |
| SBOM | Syft 1.56.0 | Inventario de componentes de la imagen |

El objetivo de pruebas es [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), una aplicación vulnerable a propósito, fijada en un commit y una imagen concretos.

> **Aviso:** Juice Shop es vulnerable por diseño. No expongas el puerto 3000 a internet.

## Requisitos

Cualquiera de estas dos opciones:

- **GitHub Codespaces** (recomendado): ya incluye Docker. Es el entorno en el que se desarrolló el trabajo.
- **Equipo propio** con Docker Engine y el plugin Docker Compose v2 (`docker compose version` debe funcionar), Git, Bash y Python 3.

Se necesita conexión a internet para descargar las imágenes y la base de datos de vulnerabilidades de Trivy.

## Inicio rápido

```bash
git clone https://github.com/Goldark17/tfm-devsecops-supply-chain.git
cd tfm-devsecops-supply-chain
bash lab/run-all.sh
```

El script:

1. Clona Juice Shop en `lab/target/` en el commit fijado (si no existe ya).
2. Genera el `package-lock.json` que el proyecto no incluye.
3. Descarga la base de datos de Trivy a una caché (este paso no se cronometra).
4. Ejecuta cada escáner con `docker compose run` y mide su tiempo.
5. Imprime una tabla resumen con hallazgos y tiempos.

Tarda entre 4 y 5 minutos. Los informes JSON y `tiempos.csv` quedan en `lab/results/`.

### Resultados esperados

Si todo ha ido bien, la tabla final debe mostrar estas cifras:

| Herramienta | Hallazgos esperados | ¿Puede variar? |
| --- | --- | --- |
| Gitleaks | 69 (3 claves privadas) | No |
| Semgrep | 43 (13 de severidad ERROR) | Solo si cambian sus reglas |
| Trivy (código) | entre 67 y 68 (9 CRITICAL) | Sí, cambia con el tiempo |
| Trivy (imagen) | entre 125 y 153 en noviembre de 2026 (11 CRITICAL) | Sí, cambia con el tiempo |
| Syft (SBOM) | 739 librerías | No |

El quality gate debe terminar en **PIPELINE BLOQUEADO**, que es lo correcto, porque Juice Shop es vulnerable a propósito.

Gitleaks y Syft analizan un commit y una imagen fijados, así que sus cifras se repiten exactamente. Semgrep también, salvo que cambien las reglas que descarga de su registro. Las de Trivy dependen de su base de datos de vulnerabilidades, que se actualiza a diario, y del `package-lock.json` generado en cada ejecución, por eso cambian aunque el objetivo no cambie. Los CRITICAL, que son los que deciden el quality gate, se han mantenido estables en todas las mediciones. Para medir los falsos positivos se usó una instantánea de los informes del 16 de noviembre de 2026, protegida con un manifiesto SHA-256 en `docs/falsos-positivos/`.

### Otros usos

```bash
cd lab
docker compose up -d                  # levanta solo Juice Shop en http://localhost:3000
docker compose run --rm -T gitleaks   # ejecuta un único escáner
docker compose down                   # para el laboratorio
```

Si Compose avisa de que el volumen `trivy-cache` ya existía, el aviso es inofensivo. Se elimina con `docker volume rm trivy-cache`.

## Estructura del repositorio

| Ruta | Contenido |
| --- | --- |
| `lab/docker-compose.yml` | Servicios del laboratorio: `juice-shop` y, en el perfil `scan`, los escáneres |
| `lab/.env` | Fuente única de versiones y digests de todas las imágenes |
| `lab/run-all.sh` | Ejecución completa del laboratorio |
| `lab/resumen.py` | Tabla resumen de resultados |
| `.github/workflows/devsecops.yml` | Pipeline de GitHub Actions |
| `docs/falsos-positivos/` | Revisión manual de falsos positivos: criterios, instantánea de informes, manifiesto SHA-256, muestra con veredictos y resumen |
| `lab/muestreo_fp.py`, `lab/resumen_fp.py`, `lab/veredictos_fp.py` | Scripts de la revisión de falsos positivos |
| `docs/` | Evidencias del endurecimiento del pipeline |

## Pipeline en GitHub Actions

El workflow se ejecuta en cada push a `main`, en cada pull request y a mano desde **Actions → DevSecOps pipeline → Run workflow**. Llama al mismo `lab/run-all.sh` que se usa en local.

Pasos: checkout, escáneres, análisis de Semgrep sobre el propio `.github/`, resumen en la página *Summary* de la ejecución, quality gate y subida de informes como artefacto (`informes-seguridad`).

### Quality gate

| Control | Umbral por defecto |
| --- | --- |
| Claves privadas (Gitleaks) | 0 |
| Dependencias CRITICAL (Trivy, código) | 0 |
| Imagen CRITICAL (Trivy) | 0 |
| Hallazgos ERROR (Semgrep) | 0 |
| Hallazgos en el propio workflow (Semgrep sobre `.github/`) | 0 |

Sobre Juice Shop el gate **bloquea** con los umbrales por defecto (ejecución en rojo), que es el comportamiento esperado. Al lanzarlo a mano se pueden subir los umbrales (`max_private_keys`, `max_critical`, `max_semgrep_error`) para comprobar que aprueba. Si falta algún informe, el gate falla en cerrado.

### Endurecimiento

- Acciones de terceros fijadas por hash de commit e imágenes fijadas por digest.
- Permisos mínimos (`contents: read`) y `persist-credentials: false`.
- Sin `pull_request_target`.

## Reproducibilidad

- Gitleaks y Syft dan los mismos recuentos en cada ejecución porque todas sus entradas están fijadas. Semgrep también, salvo que cambien las reglas de su registro.
- **Trivy cambia entre días**: su base de datos de vulnerabilidades se actualiza a diario y no está fijada. Dentro de un mismo día los recuentos son idénticos. Anota siempre la fecha de cada medición.
- El `package-lock.json` se genera a la fecha de ejecución, por lo que las versiones resueltas pueden variar con el tiempo.
- Las reglas de Semgrep se descargan de su registro en cada ejecución.

## Revisión de falsos positivos

La muestra revisada y sus veredictos están en `docs/falsos-positivos/muestra.csv`, con los criterios en `CRITERIOS.md`. La muestra se extrajo con semilla fija de una instantánea de los informes protegida por `manifiesto.txt` (SHA-256), para que no cambie aunque la base de datos de Trivy evolucione.

Para recalcular la precisión:

```bash
python3 lab/resumen_fp.py
```

El resultado se guarda en `docs/falsos-positivos/resumen-fp.md`.

## Limitaciones

- Gitleaks analiza un clon superficial (`--depth 1`), sin historial de Git.
- Trivy analiza solo dependencias de producción.
- No incluye análisis dinámico (DAST), infraestructura como código ni firma de artefactos.

## Autor

Pablo Y. del Barrio Tejero — Trabajo Fin de Máster, Máster en Ciberseguridad, Universidad Complutense de Madrid, 2026.