# Build the Windows installer: PyInstaller (usbtether.exe, no console) + Inno Setup.
#
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1
#
# Output: build\installer\usbtether-setup-<version>.exe
# Needs: the repository's virtual environment (.venv) or python on PATH, and Inno Setup 6
# (ISCC.exe on PATH, in $env:ISCC, or found through its uninstall registry entry).

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = "python" }

& $python -m pip install --quiet pyinstaller
& $python -m pip install --quiet -e .
if ($LASTEXITCODE -ne 0) { throw "pip failed" }

$version = (& $python -c "import usbtether; print(usbtether.__version__)").Trim()
Write-Host "usbtether $version"

$icon = Join-Path $root "src\usbtether\usbtether.ico"
& $python -m PyInstaller --noconfirm --clean --windowed `
    --name usbtether `
    --icon $icon `
    --add-data "$icon;usbtether" `
    --paths (Join-Path $root "src") `
    --collect-submodules usbtether `
    --distpath (Join-Path $root "build\dist") `
    --workpath (Join-Path $root "build\work") `
    --specpath (Join-Path $root "build") `
    (Join-Path $root "packaging\usbtether_entry.py")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

function Find-Iscc {
    if ($env:ISCC -and (Test-Path $env:ISCC)) { return $env:ISCC }
    $onPath = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $keys = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    foreach ($entry in Get-ItemProperty $keys -ErrorAction SilentlyContinue) {
        if ($entry.DisplayName -like "Inno Setup*" -and $entry.InstallLocation) {
            $candidate = Join-Path $entry.InstallLocation "ISCC.exe"
            if (Test-Path $candidate) { return $candidate }
        }
    }
    foreach ($dir in "${env:ProgramFiles(x86)}\Inno Setup 6", "$env:ProgramFiles\Inno Setup 6",
                     "$env:LOCALAPPDATA\Programs\Inno Setup 6") {
        $candidate = Join-Path $dir "ISCC.exe"
        if (Test-Path $candidate) { return $candidate }
    }
    throw "Inno Setup 6 not found: install it (winget install JRSoftware.InnoSetup) or set `$env:ISCC"
}

$iscc = Find-Iscc
& $iscc /Qp "/DAppVersion=$version" "/DSourceDir=$(Join-Path $root 'build\dist\usbtether')" `
    (Join-Path $root "packaging\usbtether.iss")
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }
Get-ChildItem (Join-Path $root "build\installer") -Filter *.exe | ForEach-Object { Write-Host "built $($_.FullName)" }
