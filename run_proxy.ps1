$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$mitmdump = Join-Path $projectRoot ".venv\Scripts\mitmdump.exe"
if (-not (Test-Path -LiteralPath $mitmdump)) {
    throw "Project virtual environment mitmdump not found at $mitmdump"
}

$env:AI_PRIVACY_OBSERVE = "1"
Push-Location $projectRoot
try {
    # Quiet mode prevents mitmdump from printing raw URLs or WebSocket details.
    # The addon writes its sanitized observation metadata to logs\privacy-observer.log.
    & $mitmdump -q -s proxy/proxy.py --listen-host 127.0.0.1 --listen-port 8080
} finally {
    Pop-Location
}
