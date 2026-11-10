#!/usr/bin/env bash
# Ejecuta el flujo completo del laboratorio con Docker Compose y mide tiempos.
# Uso (desde cualquier carpeta):  bash lab/run-all.sh
set -euo pipefail
cd "$(dirname "$0")"

set -a; . ./.env; set +a

mkdir -p results
rm -f results/*.json results/tiempos.csv
echo "herramienta,milisegundos" > results/tiempos.csv

# 1) Objetivo: Juice Shop en commit fijo
if [ ! -d target/juice-shop/.git ]; then
  echo ">> Preparando objetivo en commit fijo"
  git init target/juice-shop
  git -C target/juice-shop fetch --depth 1 "$JUICE_SHOP_REPO" "$JUICE_SHOP_COMMIT"
  git -C target/juice-shop checkout FETCH_HEAD
fi

timed() {
  local name=$1; shift
  echo ">> $name"
  local s e
  s=$(date +%s%N)
  "$@"
  e=$(date +%s%N)
  echo "$name,$(( (e-s)/1000000 ))" >> results/tiempos.csv
}

# 2) Escaneres (mismo orden que el pipeline de GitHub Actions)
timed gitleaks docker compose run --rm -T gitleaks
timed semgrep  docker compose run --rm -T semgrep

echo ">> Lockfile y base de datos de Trivy (no se cronometran)"
docker compose run --rm -T lockfile
docker compose run --rm -T trivy-db

timed trivy-fs docker compose run --rm -T trivy-fs

docker pull "$JUICE_SHOP_IMAGE"
timed trivy-image docker compose run --rm -T trivy-image
timed syft docker compose run --rm -T syft

# 3) Resumen
echo
python3 resumen.py