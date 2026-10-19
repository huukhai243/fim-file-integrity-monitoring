# Tao file zip sach de nop bai: dist\FIM_Project.zip
# Khong xoa hay sua gi trong thu muc dang lam viec.
# Chay: powershell -ExecutionPolicy Bypass -File .\pack.ps1

$ErrorActionPreference = 'Stop'
$root  = $PSScriptRoot
$dist  = Join-Path $root 'dist'
$stage = Join-Path ([IO.Path]::GetTempPath()) 'FIM_Project_pack'
$zip   = Join-Path $dist 'FIM_Project.zip'

# Thu muc / file khong nop: moi truong ao, cache, DB va log tu cac lan chay thu; bao cao nop rieng
$excludeDirs  = @('.venv', 'venv', '__pycache__', 'data', 'logs', 'dist', '.git', '.vscode', '.idea', '.claude', 'bao_cao')
$excludeFiles = @('*.docx', '*.doc', '~$*', '*.pyc', '*.db', '*.db-wal', '*.db-shm', '*.log.1', 'pack.ps1')

if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force $stage, $dist | Out-Null

robocopy $root (Join-Path $stage 'FIM_Project') /E /XD $excludeDirs /XF $excludeFiles /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }

if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path (Join-Path $stage 'FIM_Project') -DestinationPath $zip
Remove-Item -Recurse -Force $stage

Write-Host "Created: $zip ($([math]::Round((Get-Item $zip).Length / 1KB, 1)) KB)"
Write-Host ''
Write-Host 'Files in test_folder (check that the demo left nothing behind):'
Get-ChildItem -Recurse -File -Force (Join-Path $root 'test_folder') |
    ForEach-Object { '  ' + $_.FullName.Substring($root.Length + 1) + "  ($($_.Length) B)" }
