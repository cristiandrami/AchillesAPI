# AchillesAPI 0.27.0 — Professional reporting & bounded decision support

Built on the existing 0.23.0 source tree. This release adds conservative,
non-destructive capabilities rather than claiming full autonomous exploitation.

## Changes

- v0.24: `report` command. Sanitized HTML, JSON, Markdown and optional PDF output;
  source request bodies/headers/cookies are intentionally excluded.
- v0.25: `vulnerability-triage` creates a review queue from actual observations;
  does not call unverified evidence a confirmed vulnerability.
- v0.26: `workflow-map` proposes OpenAPI property/path name matches with
  `executable: false`, avoiding unsafe cross-resource writes.
- v0.27: `ai-prioritize` offers a deterministic, bounded GET review queue and
  optional local Ollama advisory. No network execution from model output.
- `auto-assess` results now include the offline dependency map and a triage
  summary, while retaining the existing GET/authorized disposable lifecycle.
- Version bumped; optional `pdf` extra added; regression tests extended.

## Important limitations

- NOT a general autonomous exploit engine. SQLi/NoSQLi/SSRF/SSTI, complex SSO,
  general cross-resource writes and complete business logic coverage remain open.
- Existing HTTP scope controls require independent enterprise assessment before
  treating this as production-hardened software.
- Existing evidence uses metadata; full forensic PoC validation is manual.
- Report confidence/severity are preserved as observed, not automatically
  promoted to a confirmed vulnerability.

See `docs/GUIDA_COMPLETA_V027_IT.md` for commands and the local lab setup.
