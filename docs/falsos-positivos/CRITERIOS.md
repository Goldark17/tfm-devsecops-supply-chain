# Criterios de revision de falsos positivos

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
