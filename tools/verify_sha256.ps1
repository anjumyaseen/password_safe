# Verify a file against SHA256SUMS.txt
param(
    [string]$Sums = "SHA256SUMS.txt",
    [string]$File = "dist/PasswordSafe.exe"
)

if (-not (Test-Path $Sums)) { Write-Error "Missing $Sums"; exit 1 }
if (-not (Test-Path $File)) { Write-Error "Missing $File"; exit 1 }

$expected = (Select-String -Path $Sums -Pattern [regex]::Escape($File)).Line
if (-not $expected) { Write-Error "No checksum entry for $File"; exit 1 }
$expectedHash = ($expected -split '\s+')[0].ToLower()

$actual = (Get-FileHash $File -Algorithm SHA256).Hash.ToLower()
if ($actual -eq $expectedHash) {
  Write-Host "OK  $File" -ForegroundColor Green
  exit 0
} else {
  Write-Host "MISMATCH  $File" -ForegroundColor Red
  Write-Host "Expected: $expectedHash" -ForegroundColor DarkGray
  Write-Host "Actual:   $actual" -ForegroundColor DarkGray
  exit 2
}

