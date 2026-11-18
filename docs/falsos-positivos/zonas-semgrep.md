# Hallazgos de Semgrep por zona del repositorio (43 en total)

Zona asignada por heuristica sobre la ruta; hay que comprobar los casos dudosos.

| Zona | Hallazgos | Detalle por severidad | Reglas mas frecuentes |
|---|---|---|---|
| aplicacion | 14 | WARNING 11, ERROR 3 | express-check-directory-listing (5), express-res-sendfile (4), express-sequelize-injection (2) |
| ci | 13 | WARNING 7, ERROR 6 | github-actions-mutable-action-tag (7), run-shell-injection (5), gha-curl-pipe-shell (1) |
| iac/despliegue | 10 | WARNING 10 | aws-subnet-has-public-ip-address (5), insecure-load-balancer-tls-version (5) |
| datos | 4 | ERROR 4 | express-sequelize-injection (4) |
| otros | 2 | MEDIUM 2 | npm-missing-minimum-release-age (2) |
