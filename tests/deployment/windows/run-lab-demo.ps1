# Automated, intentionally local training run. Lab API must already be running.
# The script prints what each command tests and saves structured JSON reports.
param([switch]$WithAI, [switch]$IncludeLegacyChecks, [switch]$RunWriteDemo)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $Root
$Base = 'http://127.0.0.1:8000'
$Spec = '.\examples\full_lab_openapi.json'
$Auth = '.\examples\full-lab-auth.yaml'
$Out = '.\reports\full-lab'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
try {
    $health = Invoke-RestMethod "$Base/health" -TimeoutSec 3
    if ($health.service -ne 'achillesapi-full-lab') {
        throw 'Port 8000 hosts a different service, not the expected AchillesAPI lab.'
    }
} catch {
    throw 'The lab API is not running. Start deployment/windows/start-lab.ps1 in another terminal.'
}
# Fixed credentials are only for synthetic local users, never real accounts.
$env:ACHILLES_LAB_ALICE_TOKEN = 'alice-token'
$env:ACHILLES_LAB_BOB_TOKEN = 'bob-token'
$env:ACHILLES_LAB_ADMIN_TOKEN = 'admin-token'
$env:ACHILLES_LAB_BASIC_USER = 'lab-user'
$env:ACHILLES_LAB_BASIC_PASS = 'lab-pass'
$env:ACHILLES_LAB_API_KEY = 'partner-demo-key'
$env:ACHILLES_LAB_SESSION = 'alice-session'

Write-Host 'STEP 1 - Offline Swagger analysis and security plan (no API traffic)'
uv run achillesapi analyze-openapi $Spec --output "$Out\openapi.json"
uv run achillesapi generate-tests $Spec --output "$Out\test-plan.json"
uv run achillesapi map-api $Spec --output "$Out\graph.json"
uv run achillesapi auto-assess $Spec --base-url $Base `
  --path-value order_id=order-bob --path-value username=bob `
  --path-value sku=SKU-1001 --path-value report_ref=not-created `
  --output "$Out\dry-run.json"
if ($LASTEXITCODE -ne 0) { throw 'Offline planning failed.' }

Write-Host 'STEP 2 - Authorized, bounded GET checks with six demo identities'
uv run achillesapi auto-assess $Spec --base-url $Base --allow-host 127.0.0.1 `
  --auth-config $Auth `
  --profile alice --profile bob --profile admin `
  --profile basic-demo --profile api-key-demo --profile cookie-demo `
  --path-value order_id=order-bob --path-value username=bob `
  --path-value sku=SKU-1001 --path-value report_ref=not-created `
  --max-requests 150 --rate 5 --allow-insecure-http --execute `
  --output "$Out\active-get.json"
if ($LASTEXITCODE -ne 0) { throw 'GET checks failed.' }

if ($IncludeLegacyChecks) {
    Write-Host 'STEP 3 - Explicit vulnerable vs protected endpoint demonstrations'
    uv run achillesapi bola-check "$Base/api/orders/order-bob" `
      --owner-token bob-token --other-token alice-token --execute
    uv run achillesapi bola-check "$Base/api/secure/orders/order-bob" `
      --owner-token bob-token --other-token alice-token --execute
    uv run achillesapi sqli-check "$Base/api/search" --parameter q --token alice-token
    uv run achillesapi fuzz-parameter "$Base/api/secure/search" --parameter q --token alice-token
    Write-Host 'Mass assignment: dry run only, no PATCH is sent.'
    uv run achillesapi mass-assignment-check "$Base/api/profiles/alice" `
      --body-file .\examples\full-lab-profile-patch.json --token alice-token
    Write-Host 'BFLA: all GET endpoints are compared; inspect admin/audit and admin/metrics in the JSON.'
    uv run achillesapi bfla-sweep $Spec --base-url $Base `
      --auth-config $Auth --low-profile alice --high-profile admin `
      --path-value order_id=order-bob --path-value username=bob `
      --path-value sku=SKU-1001 --path-value report_ref=not-created `
      --output "$Out\bfla-sweep.json"
}
if ($RunWriteDemo) {
    Write-Host 'STEP 4 - EXPLICIT local-only write demonstration (changes synthetic profile data)'
    uv run achillesapi mass-assignment-check "$Base/api/profiles/alice" `
      --body-file .\examples\full-lab-profile-patch.json `
      --token alice-token --execute
    uv run achillesapi mass-assignment-check "$Base/api/secure/profiles/alice" `
      --body-file .\examples\full-lab-profile-patch.json `
      --token alice-token --execute
    Write-Host 'Compare GET /api/profiles/alice to see the modified is_admin value.'
    Write-Host 'Stop/restart the lab to restore the synthetic profile to its original state.'
}
if ($WithAI) {
    Write-Host 'STEP 4 - Local Ollama analyzes Swagger and passive hypotheses (no API traffic)'
    uv run achillesapi scan $Spec --ai --model achilles-local `
      --output "$Out\ollama-passive.json"
    if ($LASTEXITCODE -ne 0) { throw 'Local AI analysis failed; run start-ai.ps1 first.' }
}
Write-Host "Demo complete. Reports written to $Out"
Write-Host 'No external API was contacted. Some lab checks are intentionally vulnerable.'
