# Últimas pruebas de Sprint 3: timeout y llavero

Estas herramientas son de laboratorio. **No ejecutarlas en el Arch del host.** La prueba de [llavero tiene su propio procedimiento](s3-keyring.md); no combinar ambos casos ni ceder el lector hasta comprobar la instrumentación en una copia desechable de la VM. No cambian el paquete ni la política PAM para obtener un resultado favorable.

## Timeout sin dedo

1. Preparar en una copia del guest el candidato x86_64 `0.21.0-3.1`, el tema Qt6 adaptado, un `bpftrace` compatible y los archivos hermanos `s3-deadline-run.sh`, `s3-deadline.bt`, `s3-deadline.py` en una carpeta de root. SDDM debe estar detenido. Confirmar `ttyS0` + `fplogin-lab recovery-check`, rollback firmado, preselección `fplab` / Hyprland, ausencia de sesión del usuario y paquete/tema verificados. Verificar antes del traspaso que `bpftrace -d s3-deadline.bt` compila y que el tracer armado en este guest sin USB emite heartbeats (sin arrancar SDDM); detenerlo. Si el kernel o la versión del tracer no lo permiten, informar BLOQUEADO, no relajar protecciones del host.
2. Tras el traspaso explícito del único lector y la verificación del nuevo arranque por ttyS0, acordar **no apoyar el dedo, pulsar F4/Enter ni iniciar otros intentos**. En la consola de root del guest ejecutar una sola vez `bash ./s3-deadline-run.sh`. Esperar a que termine. El runner inicia el greeter solamente tras la señal de vida del tracer; detiene el greeter al finalizar el caso. Nunca ejecutar simultáneamente el runner de llavero.
3. Guardar fuera de la VM el directorio privado de evidencia indicado (revisar stderr antes de exportarlo). El comprobador offline se puede repetir con `python3 s3-deadline.py DIRECTORIO`. Cerrá el guest y devolvé el lector usando el respaldo de **ese** traspaso. No hay handoff reutilizable.

**Interpretación:** `DAEMON_DEADLINE_FIRST` identifica la rama de timeout efectiva y la orden de detener el helper; `PAM_BACKSTOP_FIRST` identifica el camino de expiración de PAM y NO pasa el criterio del timeout de SDDM. Registros faltantes, otro helper/intento, pérdida de eventos u orden ambiguo no cuentan como PASS. El tiempo total de salida por sí solo no es evidencia de la causa. Se registra el valor de armado; revisar además los tiempos monotónicos y cualquier demora de despacho/limpieza antes de afirmar que se cumplió el plazo de 30 s.

**Procedencia de las sondas:** son uprobes de observación para los SHA-256 exactos del runner, no direcciones universales. En el binario dual-Qt de la VM (fuente `c05b6fb`), `0x552bc` llama a `QTimer::start(int)` en el armado; `0x5c4a9` es la llamada a `disarmFingerprintDeadline()` dentro del callback después de sus guardas; `0x515c9` llama a `QTimer::stop()`; `0x5c54f` salta al stop del helper por ese timeout. En el `pam_fprintd.so` fijado, `0x31cd` referencia `Verification timed out` dentro de `do_verify`. Estos segmentos ELF tienen `p_offset == p_vaddr`. Ante cualquier cambio de hash, **no actualizar los hashes sin volver a identificar y revisar las instrucciones**. El helper se vincula por PID, instante de creación, UUID y método del único intento; no se registra la línea de comandos completa. No es una prueba de carreras simultáneas ni de multi-monitor.

Autopruebas sin VM, lector ni privilegios:

```sh
python3 tests/integration/s3-deadline-test.py
python3 tests/integration/s3-keyring-test.py
```
