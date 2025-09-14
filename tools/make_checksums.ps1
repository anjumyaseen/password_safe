# Compute SHA256 checksums and write to SHA256SUMS.txt
param(
    [string]$OutFile = "SHA256SUMS.txt",
    [string[]]$Files = @("dist/PasswordSafe.exe")
)

Write-Host "Computing SHA256 checksums..."
$lines = @()
foreach ($f in $Files) {
    if (-not (Test-Path $f)) { Write-Error "File not found: $f"; exit 1 }
    $h = Get-FileHash $f -Algorithm SHA256
    $lines += "{0}  {1}" -f $h.Hash.ToLower(), $h.Path
}
$lines | Out-File -FilePath $OutFile -Encoding utf8 -NoNewline:$false
Write-Host "Wrote $OutFile" -ForegroundColor Green

