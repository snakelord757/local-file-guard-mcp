param([ValidateSet('stdio', 'streamable-http')][string]$Transport = 'stdio')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
& "$PSScriptRoot\.venv\Scripts\python.exe" -m gateway.server --transport $Transport
exit $LASTEXITCODE
