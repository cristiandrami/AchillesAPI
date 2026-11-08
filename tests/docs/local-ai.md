# Local AI setup (Kali Linux, CPU-only)

This release integrates Ollama as a **loopback-only** inference backend. AchillesAPI does not
support a cloud provider, remote Ollama host, API-key fallback, or automatic remote fallback.

## Recommended hardware profile

The bundled default is `llama3.2:3b` (Ollama's default quantized distribution, normally a Q4
variant). It is intended as a practical starting point for 8 GB RAM and CPU-only inference.
Keep the context at 4096 tokens and use one inference request at a time. Performance depends on
available RAM, CPU load and the exact Ollama model build. Do not run large parallel scans and
inference simultaneously on this host.

## 1. Install Ollama

Download and install Ollama using its official installation instructions while connected to the
Internet. The model weights and runtime must be downloaded once; inference itself is local.

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

## 2. Disable cloud and bind to loopback

From the repository root:

```bash
sudo ./deployment/configure-ollama-kali.sh
```

This writes a systemd override with:

- `OLLAMA_HOST=127.0.0.1:11434`
- `OLLAMA_NO_CLOUD=1`
- one parallel inference and one loaded model

Verify the listener:

```bash
ss -lntp | grep 11434
```

It should listen only on `127.0.0.1:11434`, not `0.0.0.0` or a LAN address.

## 3. Download and create the AchillesAPI model

```bash
ollama pull llama3.2:3b
ollama create achilles-local -f deployment/Modelfile
ollama list
```

The `pull` step requires Internet access. Once the model is present, inference can run offline.
For a fully air-gapped workstation, transfer the Ollama model store using an approved offline
media process. Do not copy customer data to an online model service.

## 4. Verify local inference

```bash
ollama run achilles-local "Rispondi in italiano: cosa significa BOLA in una API REST?"
```

Check the local HTTP API:

```bash
curl --fail http://127.0.0.1:11434/api/tags
```

## 5. Run AchillesAPI with local AI

Install project dependencies:

```bash
uv sync --extra dev
```

Passive scan without AI (no target requests):

```bash
uv run achillesapi scan examples/local_bola_lab_openapi.json \
  --output reports/scan-passive.json
```

Passive scan plus local AI interpretation:

```bash
uv run achillesapi scan examples/local_bola_lab_openapi.json \
  --ai --model achilles-local --output reports/scan-local-ai.json
```

Or call the AI analysis directly:

```bash
uv run achillesapi ai-analyze examples/local_bola_lab_openapi.json \
  --model achilles-local --output reports/ai-analysis.json
```

The `scan` command parses the OpenAPI document and runs deterministic passive checks. With
`--ai`, it sends sanitized OpenAPI metadata and deterministic hypotheses to Ollama. It does
**not** send requests to the API target and does not perform active vulnerability testing.

## Privacy and security model

- The Python AI connector accepts only `localhost`, `127.0.0.1`, or `::1` on HTTP and uses the
  Ollama `/api/chat` endpoint. Remote endpoints are rejected before connecting.
- There is no cloud-provider integration or remote fallback in this code path.
- Credentials and common sensitive fields are redacted before model input. This is best-effort
  protection, not a substitute for data minimization: inspect the data you feed the tool.
- The AI is advisory. It cannot issue HTTP requests, change scan scope, or confirm vulnerabilities.
- The deterministic scanner remains authoritative for its own evidence. Model output is not a
  security finding and must be reviewed by the operator.
- `OLLAMA_NO_CLOUD=1` disables Ollama cloud features, but downloading Ollama and model weights
  still requires network access. For strict offline assurance, disconnect the host or apply an
  outbound-deny firewall policy after installation and verify network behavior in your own
  environment.
- The API target may still be contacted by separate active-testing commands. Only run those
  commands against explicitly authorized systems.

## Troubleshooting

**Connection refused**

```bash
sudo systemctl status ollama --no-pager
sudo systemctl restart ollama
curl --fail http://127.0.0.1:11434/api/tags
```

**Model not found**

```bash
ollama list
ollama pull llama3.2:3b
ollama create achilles-local -f deployment/Modelfile
```

**Out of memory / very slow inference**

Close memory-heavy applications, keep only one model loaded, and use the default 4096-token
context. On an 8 GB machine, do not increase context or run concurrent model requests. If the
model still does not fit comfortably, use `llama3.2:1b` by creating a separate Modelfile with
`FROM llama3.2:1b` and keep the model name in the CLI set to that local tag.
