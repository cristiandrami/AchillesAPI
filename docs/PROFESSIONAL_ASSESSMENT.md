# AchillesAPI — professional API assessment guide (v0.11.0)

## Purpose

AchillesAPI uses the **OpenAPI file of the real target**, not any built-in lab
endpoints. The local training application is strictly optional. No module in
`core/smart.py` imports a lab module, requires the words `alice`, `admin`, or
`order`, or uses fixed tokens or resource IDs.

### A. Start with only an API specification

```powershell
uv python install 3.12
uv sync --python 3.12 --extra dev
uv run achillesapi auto-assess .\swagger.yaml --output .\reports\plan.json
```

If the spec contains one absolute `servers[0].url`, AchillesAPI uses it. If
there are multiple servers or no absolute server, add `--base-url` manually.
This step is **offline**. The JSON shows every operation, the chosen test
modules, missing inputs and non-GET actions that require manual review.

### B. Add permitted test accounts if the API needs authentication

Edit a copy of `examples/professional/auth-profiles.yaml`. Profile names are
arbitrary; credentials come from environment variables. For example:

```powershell
$env:ACHILLES_MAIN_TOKEN = "<approved-main-test-token>"
$env:ACHILLES_SECOND_TOKEN = "<approved-second-test-token>"
```

Do not commit tokens to Git. `--auth-config` automatically selects all profiles
if `--profile` is omitted. The framework selects which credentials to send
to each endpoint based on the OpenAPI security declaration. Bearer tokens can
also be used for OAuth2/OIDC-protected endpoints; token acquisition and scope
management are not implemented yet.

### C. Provide missing IDs, ownership and role facts when necessary

Create your own `engagement-context.yaml`, starting from
`examples/professional/engagement-context.yaml`.

The optional `path_values` mapping resolves **specific named path/query
parameters**, e.g. `account_ref: TEST-ACCOUNT-001`. Values should point to
approved disposable test data. OpenAPI cannot reliably discover real owners or
role policies.

For higher-confidence authorization checks, add `expected_access` with exact
method + OpenAPI path template and the expected `allow`/`deny` result per
profile. Without it, the scanner still compares accounts, but makes no
positive BOLA/BFLA assertions from status or body similarity alone.

### D. Execute an authorized automatic scan

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.org/api `
  --allow-host staging.example.org `
  --auth-config .\auth-profiles.yaml `
  --context .\engagement-context.yaml `
  --max-requests 60 `
  --rate 1 `
  --execute `
  --output .\reports\professional-assessment.json
```

With the explicit `--execute`, the engine automatically:

1. Checks each declared GET operation for missing inputs and applicable auth.
2. Performs a normal GET baseline with compatible identities.
3. Looks for server errors, implementation disclosures, risky caching, and
   returned response properties marked `writeOnly` or sensitive by schema.
4. On endpoints declared authenticated, checks the unauthenticated response.
5. Sends a bounded Origin-header probe to detect potentially risky CORS rules.
6. Chooses a small invalid value for supported query parameter types and
   examines validation failures (no destructive SQLi payloads).
7. Compares access against provided ownership/role expectations, if present.
8. Produces metadata-only evidence and a reviewable list of observations.

It respects the **single combined request budget** across all identities and
checks, a shared rate, short timeouts, TLS verification, and redirects disabled.
`--execute` never authorizes write methods. OAuth token acquisition and
automatic business workflow setup/teardown are not implemented yet.

### E. Optional local Ollama interpretation

When Ollama is already running locally and `achilles-local` is installed:

```powershell
uv run achillesapi auto-assess .\swagger.yaml `
  --base-url https://staging.example.org/api `
  --allow-host staging.example.org `
  --auth-config .\auth-profiles.yaml `
  --context .\engagement-context.yaml `
  --max-requests 60 --execute --ai --model achilles-local `
  --output .\reports\professional-with-ai.json
```

The AI receives sanitized scanner findings and endpoint metadata only. It is
advisory and **cannot** make arbitrary requests, expand the allowed scope,
change methods, decide permissions, or declare a vulnerability confirmed.
There is no cloud fallback.

### F. Work with missing or problematic inputs

- `blocked_missing_inputs`: supply an approved test value for a named path or
  required query parameter. The scanner does not invent existing customer IDs.
- `manual_only_non_get`: the method can modify data and needs an approved
  disposable fixture, a rollback plan, and an explicit controlled action.
- `missing_compatible_auth_profile`: configure the required scheme; no token
  is leaked to an unrelated authentication mechanism.
- `request_budget_exhausted`: increase `--max-requests` only after checking
  permitted traffic volume in the engagement scope.
- For operations that change state even when using GET, do not execute an
  active scan without an explicit safe-endpoint list from the API owner.

### G. Tuning

`--max-probes-per-endpoint 0` disables invalid-query probes (or use
`--no-validation`). `--no-cors` and `--no-auth-checks` disable their respective
modules. The default mode is always dry-run.

### What this release does NOT prove

- An HTTP `200` is not proof of BOLA/BFLA; some data is legitimately public.
- Repeated content between identities is not proof of an ownership violation.
- A CORS reflection indicator needs an actual browser exploitability review.
- A server error following invalid input is not proof of SQL injection.
- OpenAPI cannot supply all session, business workflow, or tenant facts.
- The tool is not a substitute for human validation and methodology in a
  professional engagement, nor is it yet a comprehensive automated pentester.

## Code map

| File | Responsibility |
| --- | --- |
| `core/openapi.py` | Offline OpenAPI parsing/normalization |
| `core/generic.py` | Universal endpoint inventory, placeholders and auth scheme matching |
| `core/smart.py` | Decide and execute checks dynamically from response evidence |
| `core/context.py` | Read optional engagement facts and access expectations |
| `core/auth.py` | Credentials from environment-backed profiles |
| `core/http.py` | Shared bounded, scoped HTTP transport |
| `core/testgen.py` | Offline security test suggestions |
| `ai/intelligence.py` | Local advisory correlation, never execution |
| `cli.py` | CLI parameters, security gating and output |

Read the docstring above each function for input, side effects, assumptions and
what it returns. `tests/test_smart.py` shows integration with an unrelated API.
