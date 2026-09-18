# Starts the realtime server for local development.
#
# Nothing here names this machine's LAN address, so joining a different network
# needs no edit: the allowed origins are wildcards over the private ranges, and
# the WebSocket URL handed to clients is derived from each bootstrap request's
# own Host header (WEBSOCKET_URL is deliberately left unset).
#
# The JWT key pair and the internal HMAC secret are shared with the .NET API,
# which keeps them in dotnet user-secrets. They are read from there rather than
# written here so the two services cannot drift apart, and so no secret lands in
# this file or in shell history.

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$goRoot = Join-Path $repoRoot "go-realtime"

# The id is declared in mypolnew.csproj; keep the two in step if it ever changes.
$secretsId = "47bd5a3d-5107-465f-97af-e2009d19b9f9"
$secretsPath = Join-Path $env:APPDATA "Microsoft\UserSecrets\$secretsId\secrets.json"

if (-not (Test-Path $secretsPath)) {
    throw "No user-secrets found at $secretsPath. Set the API's secrets first."
}
$secrets = Get-Content $secretsPath -Raw | ConvertFrom-Json

$env:HTTP_ADDR = ":8081"
$env:CANVAS_JWT_PUBLIC_KEY_FILE = "./keys/canvas-public.pem"

# Any address in the private IPv4 ranges, on the Next dev-server port. The
# wildcard stops at "/", so these cannot be satisfied by a hostile origin's path.
# 172.16-172.31 is spelled out rather than wildcarded because "172.*" would also
# admit public space.
$origins = @("http://localhost:3000", "http://127.0.0.1:3000",
             "http://192.168.*.*:3000", "http://10.*.*.*:3000")
$origins += 16..31 | ForEach-Object { "http://172.$_.*.*:3000" }
$env:ALLOWED_ORIGINS = $origins -join ","

$env:INTERNAL_HMAC_CURRENT_KEY_ID = $secrets.'CanvasRealtime:Internal:CurrentKeyId'
$env:INTERNAL_HMAC_CURRENT_SECRET = $secrets.'CanvasRealtime:Internal:CurrentSecret'

$env:EPHEMERAL_BINARY_ENABLED = "true"

Push-Location $goRoot
try {
    # This tree is a git checkout of its own, but stamping still fails in some
    # working copies; disabling it keeps `go run` usable either way.
    $env:GOFLAGS = "-buildvcs=false"
    go run ./cmd/server
}
finally {
    Pop-Location
}
