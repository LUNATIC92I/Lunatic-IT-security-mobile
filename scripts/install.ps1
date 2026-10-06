# LUNATIC MOBILE SECURITY - installation script for Windows (PowerShell).
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 [-Dev] [-Shortcut]
#   -Dev       also installs the test and build tools (pytest, ruff, build)
#   -Shortcut  creates a Start Menu shortcut
param([switch]$Dev, [switch]$Shortcut)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

Write-Host "==> Plateforme detectee : Windows ($env:PROCESSOR_ARCHITECTURE)"

$python = $null
foreach ($candidate in @("py -3", "python")) {
    $exe, $args0 = $candidate.Split(" ", 2)
    if (Get-Command $exe -ErrorAction SilentlyContinue) {
        $ok = & $exe @($args0 | Where-Object { $_ }) -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) { $python = $candidate; break }
    }
}
if (-not $python) {
    Write-Error "ERREUR : Python 3.10+ introuvable. ACTION : installez-le depuis https://www.python.org/downloads/ (cochez 'Add to PATH')."
}
$exe, $args0 = $python.Split(" ", 2)
Write-Host "==> Python : $(& $exe @($args0 | Where-Object { $_ }) --version)"

if (-not (Test-Path ".venv")) {
    Write-Host "==> Creation de l'environnement virtuel .venv"
    & $exe @($args0 | Where-Object { $_ }) -m venv .venv
}
$venvPython = ".venv\Scripts\python.exe"
& $venvPython -m pip install --upgrade pip | Out-Null
if ($Dev) { & $venvPython -m pip install -r requirements-dev.txt } else { & $venvPython -m pip install -r requirements.txt }

if ($Shortcut) {
    $projectDir = (Get-Location).Path
    $programs = [Environment]::GetFolderPath("Programs")
    $link = Join-Path $programs "LUNATIC MOBILE SECURITY.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $item = $shell.CreateShortcut($link)
    $item.TargetPath = Join-Path $projectDir ".venv\Scripts\python.exe"
    $item.Arguments = "-m app.main"
    $item.WorkingDirectory = $projectDir
    $item.Description = "Audit de securite Android et installation officielle de GrapheneOS"
    $item.Save()
    Write-Host "==> Raccourci cree : $link"
}

Write-Host "==> Diagnostic de l'environnement"
& $venvPython -m app.main --check

Write-Host ""
Write-Host "Installation terminee."
Write-Host "Lancer l'application : .venv\Scripts\python.exe -m app.main"
