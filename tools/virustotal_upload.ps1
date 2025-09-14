# Upload a file to VirusTotal for scanning.
# Requires a VT API key with file scanning permission.
# Set environment variable VT_API_KEY or pass -ApiKey.

param(
  [string]$File = "dist/PasswordSafe.exe",
  [string]$ApiKey = $env:VT_API_KEY
)

if (-not $ApiKey) { Write-Error "Set VT_API_KEY environment variable or pass -ApiKey"; exit 1 }
if (-not (Test-Path $File)) { Write-Error "File not found: $File"; exit 1 }

$Headers = @{ "x-apikey" = $ApiKey }
$Form = @{ file = Get-Item $File }

Write-Host "Uploading to VirusTotal..." $File
$resp = Invoke-RestMethod -Method Post -Uri "https://www.virustotal.com/api/v3/files" -Headers $Headers -Form $Form

if ($resp.data.id) {
  $analysis = $resp.data.id
  $url = "https://www.virustotal.com/gui/file-analysis/$analysis"
  Write-Host "Submitted. Analysis URL:" $url -ForegroundColor Green
} else {
  $resp | ConvertTo-Json -Depth 4
}

