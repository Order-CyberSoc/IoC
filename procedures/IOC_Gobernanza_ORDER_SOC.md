[Uploading IOC_Gobernanza_ORDER_SOC.md…]()
# ORDER TECHNOLOGY · Procedimiento SOC-CTI-001

**Gestión de indicadores de compromiso (IOC) — v2.3**  
**Propietario:** Responsable SOC / Threat Intelligence  
**Estado:** Procedimiento propuesto, sujeto a aprobación interna  
**Clasificación:** Uso interno SOC. La inteligencia de clientes se almacena en un repositorio privado autorizado.

## 1. Objetivo y alcance

Definir un ciclo auditable de **ingreso, validación de existencia, verificación técnica, aprobación, monitoreo, bloqueo autorizado, expiración y retiro** de IOC para FortiGate, FortiAnalyzer, FortiManager y recursos Fortinet/Cisco administrados. No confundir recopilación de inteligencia con detección real ni bloqueo en un cliente. FortiSwitch/FortiAP y Cisco switches/AP actúan preferentemente como mecanismos de contención de endpoints, no como consumidores de blacklist WAN.

**Fuera de alcance inicial:** automatización del bloqueo; publicación indiscriminada de IOC de terceros; atribución de incidentes a clientes sin telemetría.

## 2. Campos obligatorios del ticket

ID de caso/RFC, fecha UTC, tipo (`ip`, `domain`, `sha256`), valor original y normalizado, fuente y enlace/evidencia, campaña/familia si aplica, primera/última observación, puertos asociados si los hay, confianza de la fuente, clientela/entorno autorizado (TI/OT), analista proponente, verificador, aprobador, riesgo de impacto, estado, fecha de expiración, excepción/rollback, evidencia posterior a intervención. **No incorporar información sensible del cliente al repositorio GitHub público.**

## 3. Matriz RACI operativa

| Actividad | Analista CTI/SOC | Revisor independiente | Líder SOC / Cambio | Operaciones FW / Cliente |
|---|---|---|---|---|
| Registrar IOC y ticket | R | C | I | I |
| Validar formato, existencia y fuente | R | A | I | I |
| Hunting y correlación | R | C | I | C |
| Autorizar bloqueo / excepción / retiro | C | R | A | C/A según contrato |
| Implementar bloqueo aprobado | I | C | A | R |
| Verificar eficacia y reversión | R | R | A | R |

**R** ejecuta; **A** autoriza; **C** consulta; **I** informado. El mismo analista no puede proponer, verificar y aprobar un bloqueo.

## 4. Flujo y estados

`candidate` → `verified` → `approved_monitoring` o `approved_blocking` → `revoked` / `expired`.

La verificación puede conducir a `rejected`. La prioridad `P1-hunting` **no es autorización de bloqueo**. Un IOC revocado permanece en registro de auditoría, no debe borrarse de la evidencia.

### 4.1 Alta / propuesta

1. Crear ticket e indicar fuente (ThreatFox, URLhaus, FortiGuard, Cisco Talos, FAZ, EDR, etc.).
2. Normalizar y validar la estructura: IPv4 global, dominio FQDN normalizado o hash SHA256 de 64 caracteres hexadecimales.
3. Ejecutar el comando `check` para buscar coincidencia **exacta** en feeds legacy, feeds de revisión, historial y registro de decisiones.
4. Si existe, actualizar ticket y no duplicar propuesta. Si no existe, crear `candidate` con fuente, justificación y evidencia.

### 4.2 Verificación técnica independiente

1. Confirmar **al menos una evidencia verificable** y fecha de observación; no asumir vigencia solo por presencia en una lista.
2. Distinguir IOC `IP:puerto` de IP completa. El indicador `1.2.3.4:443` no autoriza bloquear `1.2.3.4` en todos los servicios.
3. Inspeccionar uso de CDN/hosting compartido, DNS, dependencias de SaaS, servicios del cliente, rutas DC/HUB, OT, VPN y plataformas cloud.
4. Verificar posibles falsos positivos, revisiones del fabricante y reglas de excepción (allowlist).
5. Buscar coincidencias en FortiAnalyzer/SIEM *por cliente*, incluyendo equipo origen, política, tiempo y acción. No considerar una coincidencia como compromiso confirmado.
6. Registrar resultado `confirmed` o `rejected`, con revisor distinto del proponente.

### 4.3 Aprobación

- **Monitoring**: aprobado para hunting, perfil en monitor o seguimiento; no implica inserción en una política.
- **Blocking**: requiere responsable distinto, ticket/RFC, evaluación de impacto, fecha de caducidad, alcance exacto, ventana/rollback si es necesario, y aprobación del cliente cuando su procedimiento de cambios lo requiera.
- Orden de preferencia: bloquear URL/hostname exacto cuando la evidencia está limitada a URL/hostname; bloquear hash exacto cuando la inspección AV es compatible; bloquear IP completa solo si la evidencia e impacto lo justifican.
- Priorizar un piloto antes de distribuir mediante FMG. En OT aplicar proceso de autorización más estricto.

### 4.4 Publicación y verificación posterior

1. Aprobación formal visible en ticket; revisión de PR y branch protection.
2. Publicar únicamente IOC autorizados en el feed de *producción* correspondiente; el pipeline v2.3 **no lo hace automáticamente**.
3. Verificar que el FortiGate descargó el feed, que la política/perfil lo referencia y que su prioridad es la correcta.
4. Verificar logs de deny en FortiAnalyzer (forward/local-in según el caso), respetando local-in y puertos administrativos reales (por ejemplo HTTPS 10443 en CyD_Santiago).
5. Guardar evidencia antes/después y resultado del cambio. Registrar total de bloqueos **observados**, no inferidos.

### 4.5 Revocación / retiro / vencimiento

- Causales: TTL vencido, fuente revoca, falso positivo, evento de cambio, dependencia crítica, autorización caducada.
- Crear ticket de retiro con motivo y aprobador; marcar `revoked` en registro; identificar feed, políticas, local-in y alcance por cliente.
- Retirar manualmente la entrada del feed aprobado correspondiente; mantener respaldos y auditar propagación a FortiGate/FMG/FAZ.
- Si se detecta interrupción real, ejecutar rollback bajo procedimiento de emergencia y escalar al SOC.
- **La salida del historial (`ioc-state`) no retira un IOC de `ips.txt` ni de ningún FortiGate automáticamente.**

## 5. Ejemplo de uso CLI del registro local

El registro por defecto queda en `build/soc-ioc-decisions.json` y **no publica nada en GitHub ni modifica firewalls**.

```bash
python scripts/ioc_lifecycle.py check --type ip --value 76.76.21.98 --root . --history build/current-history.json
python scripts/ioc_lifecycle.py propose --type ip --value 76.76.21.98 --actor analista01 --ticket SOC-2026-001 --source ThreatFox --evidence-url https://example.org/evidence --reason "IOC para verificar; infraestructura compartida"
python scripts/ioc_lifecycle.py verify --type ip --value 76.76.21.98 --actor analista02 --verdict confirmed --notes "Verificado en fuente y con alcance acotado"
python scripts/ioc_lifecycle.py approve --type ip --value 76.76.21.98 --actor lider-soc --ticket SOC-2026-001 --decision monitor --expires-on 2026-11-30
python scripts/ioc_lifecycle.py revoke --type ip --value 76.76.21.98 --actor lider-soc --ticket SOC-2026-001 --reason "Indicación revocada o expiración"
```

> **Ejemplos solamente:** fechas/tickets/actores ilustrativos. Antes de bloqueo IP global revisar la evidencia e impacto; en la herramienta `approve --decision block` se exige `--ack-risk` y un `--scope` explícito.

## 6. Controles del repositorio / segregación

- `main`: código aprobado; archivos legacy intactos.
- `feeds`: cambios de desarrollo sujetos a PR y revisión.
- `ioc-state`: snapshots y reportes técnicos; **revisar privacidad y términos de fuentes externas** dado que el repositorio actualmente es público.
- `build/`: estado de decisiones y artefactos privados locales, fuera de git; usar una base privada para conservación operativa.
- `ips-critical.txt` solo debe incluir IOC aprobados tras el proceso del SOC; el nombre de un archivo no acredita su validación.

## 7. Retención, indicadores y notificación

- Reevaluación diaria de IOC y TTL según tipo; conservar evidencia y logs de aprobación bajo las políticas del cliente.
- Reporte diario SOC: altas/bajas entre snapshots; diferencias no equivalen a despliegues.
- Reporte semanal cliente: agregados y advertencias de cobertura; no mostrar IOC crudos si licencia/confidencialidad no lo permite; no atribuir incidentes si FAZ no está integrado por cliente.
- Medir: IOC nuevos, caducados, validados, aprobados, rechazados, match en logs verificados, falsos positivos, tiempo de aprobación y tiempo de retiro.

## 8. Condiciones de activación del bloqueo automatizado futuro

**No activar** hasta: doble revisión, allowlist central, excepciones por cliente, reputación y antigüedad, verificación CDN, límites de cambios, rollback probado, control de acceso, pruebas en FortiGate 7.2.x/7.4.x, aprobación contractual y SLA de monitoreo. La v2.3 es *review-only*.
