# AGENTS.md — `@stealthmark/mcp-server`

## Compuerta Obligatoria de Jurado (3 Jueces en Contexto Limpio)
Después de correr `typecheck` y tests locales, y **antes** de proponer cualquier actualización, `commit`, `push` o publicación, invocá **3 jueces independientes** (el modelo más capaz disponible, contexto limpio) ante:
- Actualizaciones funcionales/tools MCP, cambios de dependencias o pre-commit/pre-release.
- Validación o fix de bugs en resolución de manifiestos (`gateway_resolve`), invocación (`gateway_invoke`) o consultas (`kya_status`).
- Todo lo referido a ciberseguridad y OPSEC: validación estricta con `zod`, manejo seguro de Bearer tokens (`STEALTHMARK_API_KEY`, nunca loguear ni exponer credenciales), prevención de SSRF/URL injection en `--api-url` o dominios externos, timeouts y manejo robusto de errores en stdio.
- Cambios críticos en contratos de entrada/salida de herramientas MCP, transporte stdio o dependencias públicas del SDK.

Roles: **1. Técnico/Contratos MCP/Tests**, **2. Ciberseguridad/OPSEC/Anti-SSRF**, **3. Producto/UX/Zero-Humo/Calidad**. Formato: `VEREDICTO: APROBADO | APROBADO CON CORRECCIONES | NO APROBADO` (`VETO`/`CRÍTICO`/`ALTO`/`BLOQUEANTE`/`MEDIO`/`BAJO`). Todo `VETO`/`CRÍTICO`/`ALTO`/`BLOQUEANTE` se corrige y exige re-correr `npm run typecheck && npm test` **tras la última edición**. Cualquier `NO APROBADO` bloquea. Un `VETO` o `CRÍTICO` vuelve siempre al juez que lo levantó para una sola re-verificación del fix; el resto la necesita solo si el fix toca arquitectura, autenticación/perímetro, aritmética crítica, contratos públicos o la superficie de seguridad. La verificación en vivo es solo sobre servicios propios en local o staging. Ningún `VEREDICTO` es el "sí": commit, push y publicación siguen necesitando el visto bueno explícito del mantenedor. Excepción única: consultas de solo lectura o typos triviales sin impacto técnico, operativo, normativo ni de seguridad. Sin subagentes: `code-review-and-quality` (o `thermo-nuclear-review` + `thermo-nuclear-code-quality-review`) + `security` por separado, rotulado "revisión fallback (no jurado)" y sin línea `VEREDICTO`.

## Verificación Mínima
```zsh
npm run typecheck && npm test
```
