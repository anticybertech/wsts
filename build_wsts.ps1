<#
.SYNOPSIS
    Build, sign, hash and package a WSTS release.

.DESCRIPTION
    1. Build the PyInstaller folder build (dist\WSTS) from wsts.spec.
    2. Sign dist\WSTS\WSTS.exe with Microsoft Artifact Signing.
    3. Compile the Inno Setup installer (downloads\WSTS-Setup-<ver>.exe).
    4. Sign the installer.
    5. Verify both signatures chain to a trusted root (refuses to publish a
       self-signed or unsigned build unless -AllowUnsigned is given).
    6. Write the .sha256 sidecar and release.json for the website.

.PARAMETER Version
    Release version, e.g. 1.0.1. Must match version_wsts.txt.

.PARAMETER CertProfile
    Artifact Signing certificate profile name (created after identity
    validation completes). Required unless -AllowUnsigned.

.PARAMETER SigningAccount
    Artifact Signing account name. Default: antibodycybersign

.PARAMETER SigningEndpoint
    Region endpoint of the account. Default: https://eus.codesigning.azure.net

.PARAMETER DlibPath
    Path to Azure.CodeSigning.Dlib.dll (x64). Auto-detected if omitted.

.PARAMETER SignToolPath
    Path to signtool.exe (x64, Windows SDK 10.0.22621+). Auto-detected if omitted.

.PARAMETER IsccPath
    Path to Inno Setup's ISCC.exe. Auto-detected if omitted.

.PARAMETER BuildBootloader
    Reinstall PyInstaller from source so its bootloader is compiled locally
    (needs Visual Studio Build Tools). A unique bootloader avoids sharing the
    stock one that many malware samples also use.

.PARAMETER AllowUnsigned
    Build without signing (testing only). release.json will say signed=false.

.EXAMPLE
    az login
    .\build_wsts.ps1 -Version 1.0.1 -CertProfile wsts-public

.NOTES
    Prerequisites (one time):
      winget install -e --id Microsoft.Azure.ArtifactSigningClientTools
      winget install -e --id JRSoftware.InnoSetup
      pip install -r requirements.txt
    You must hold the "Artifact Signing Certificate Profile Signer" role, and
    be signed in with `az login` (the dlib uses DefaultAzureCredential).
#>

[CmdletBinding()]
param(
    [string]$Version = "1.0.1",
    [string]$CertProfile = "",
    [string]$SigningAccount = "antibodycybersign",
    [string]$SigningEndpoint = "https://eus.codesigning.azure.net",
    [string]$DlibPath = "",
    [string]$SignToolPath = "",
    [string]$IsccPath = "",
    [switch]$BuildBootloader,
    [switch]$AllowUnsigned
)

$ErrorActionPreference = "Stop"
$Root      = $PSScriptRoot
$SpecFile  = Join-Path $Root "wsts.spec"
$IssFile   = Join-Path $Root "wsts.iss"
$AppExe    = Join-Path $Root "dist\WSTS\WSTS.exe"
$OutDir    = Join-Path $Root "downloads"
$FinalName = "WSTS-Setup-$Version.exe"
$FinalExe  = Join-Path $OutDir $FinalName
$Manifest  = Join-Path $OutDir "release.json"
$Timestamp = "http://timestamp.acs.microsoft.com"

function Find-First([string[]]$Candidates) {
    foreach ($c in $Candidates) {
        $hit = Get-ChildItem -Path $c -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

Write-Host "=== WSTS release build $Version ===" -ForegroundColor Cyan

# ── Version sanity check ───────────────────────────────────────────────────
$verText = Get-Content (Join-Path $Root "version_wsts.txt") -Raw
if ($verText -notmatch [regex]::Escape("'FileVersion', '$Version.0'")) {
    throw "version_wsts.txt does not say FileVersion $Version.0 — update it first."
}
$appText = Get-Content (Join-Path $Root "win_scanner_app.py") -Raw
if ($appText -notmatch [regex]::Escape("__version__ = `"$Version`"")) {
    throw "win_scanner_app.py __version__ is not $Version — update it first."
}

$sign = -not $AllowUnsigned
if ($sign -and -not $CertProfile) {
    throw "Pass -CertProfile <name> (Artifact Signing certificate profile), or -AllowUnsigned for a test build."
}

# ── Locate tools ───────────────────────────────────────────────────────────
if ($sign) {
    if (-not $SignToolPath) {
        $SignToolPath = Find-First @(
            "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.*\x64\signtool.exe",
            "$env:LOCALAPPDATA\Microsoft\WindowsApps\signtool.exe")
    }
    if (-not $DlibPath) {
        $DlibPath = Find-First @(
            "$env:ProgramFiles\Microsoft\*Signing*\**\x64\Azure.CodeSigning.Dlib.dll",
            "${env:ProgramFiles(x86)}\Microsoft\*Signing*\**\x64\Azure.CodeSigning.Dlib.dll",
            "$env:LOCALAPPDATA\Microsoft\*Signing*\**\x64\Azure.CodeSigning.Dlib.dll",
            "$Root\tools\**\x64\Azure.CodeSigning.Dlib.dll")
        if (-not $DlibPath) {
            $DlibPath = Get-ChildItem -Path "$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:LOCALAPPDATA" `
                -Recurse -Filter Azure.CodeSigning.Dlib.dll -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -like "*\x64\*" } | Select-Object -First 1 -ExpandProperty FullName
        }
    }
    if (-not (Test-Path $SignToolPath)) { throw "signtool.exe not found. Install the Windows SDK or pass -SignToolPath." }
    if (-not (Test-Path $DlibPath))     { throw "Azure.CodeSigning.Dlib.dll not found. Install Artifact Signing Client Tools or pass -DlibPath." }
    Write-Host "  signtool : $SignToolPath"
    Write-Host "  dlib     : $DlibPath"
}
if (-not $IsccPath) {
    $IsccPath = Find-First @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe")
}
if (-not $IsccPath -or -not (Test-Path $IsccPath)) { throw "ISCC.exe not found. Install Inno Setup 6 or pass -IsccPath." }

$MetaFile = Join-Path $env:TEMP "wsts-signing-metadata.json"
if ($sign) {
    [ordered]@{
        Endpoint               = $SigningEndpoint
        CodeSigningAccountName = $SigningAccount
        CertificateProfileName = $CertProfile
        CorrelationId          = "wsts-$Version"
    } | ConvertTo-Json | Set-Content -Path $MetaFile -Encoding utf8
}

function Invoke-Sign([string]$File) {
    if (-not $sign) { return }
    Write-Host "  signing $File" -ForegroundColor DarkCyan
    & $SignToolPath remove /s $File 2>$null | Out-Null   # strip any old signature
    & $SignToolPath sign /v /fd SHA256 /tr $Timestamp /td SHA256 `
        /d "WSTS - Windows Security Threat Scanner" `
        /dlib $DlibPath /dmdf $MetaFile $File
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed ($LASTEXITCODE) for $File" }
    & $SignToolPath verify /pa /tw $File | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signtool verify failed for $File" }
    $sig = Get-AuthenticodeSignature $File
    if ($sig.Status -ne "Valid") { throw "Signature on $File is '$($sig.Status)', expected Valid." }
    if ($sig.SignerCertificate.Subject -eq $sig.SignerCertificate.Issuer) {
        throw "Signature on $File is self-signed. Refusing to publish."
    }
    Write-Host "    OK: $($sig.SignerCertificate.Subject)" -ForegroundColor Green
}

# ── 0. Optional: compile PyInstaller bootloader locally ────────────────────
if ($BuildBootloader) {
    Write-Host "[0/6] Rebuilding PyInstaller with a locally compiled bootloader..." -ForegroundColor Yellow
    $env:PYINSTALLER_COMPILE_BOOTLOADER = "1"
    python -m pip install --force-reinstall --no-binary pyinstaller pyinstaller
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller source build failed (Visual Studio Build Tools installed?)" }
}

# ── 1. Build ───────────────────────────────────────────────────────────────
Write-Host "[1/6] Building with PyInstaller (folder build)..." -ForegroundColor Yellow
Push-Location $Root
try { pyinstaller $SpecFile --clean --noconfirm } finally { Pop-Location }
if (-not (Test-Path $AppExe)) { throw "Build failed: $AppExe not found." }

# ── 2. Sign the app ────────────────────────────────────────────────────────
Write-Host "[2/6] Signing WSTS.exe..." -ForegroundColor Yellow
Invoke-Sign $AppExe

# ── 3. Installer ───────────────────────────────────────────────────────────
Write-Host "[3/6] Compiling installer..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
& $IsccPath "/DAppVersion=$Version" $IssFile
if ($LASTEXITCODE -ne 0) { throw "ISCC failed ($LASTEXITCODE)" }
if (-not (Test-Path $FinalExe)) { throw "Installer not found: $FinalExe" }

# ── 4. Sign the installer ──────────────────────────────────────────────────
Write-Host "[4/6] Signing installer..." -ForegroundColor Yellow
Invoke-Sign $FinalExe

# ── 5. Hash ────────────────────────────────────────────────────────────────
Write-Host "[5/6] Computing SHA-256..." -ForegroundColor Yellow
$hash   = (Get-FileHash $FinalExe -Algorithm SHA256).Hash.ToLower()
$size   = (Get-Item $FinalExe).Length
$sizeMb = "{0:N1} MB" -f ($size / 1MB)
"$hash  $FinalName" | Out-File -FilePath "$FinalExe.sha256" -Encoding ascii -NoNewline

# ── 6. Manifest ────────────────────────────────────────────────────────────
Write-Host "[6/6] Writing release.json..." -ForegroundColor Yellow
$sig = Get-AuthenticodeSignature $FinalExe
$signedOk = ($sig.Status -eq "Valid")
[ordered]@{
    product        = "WSTS - Windows Security Threat Scanner"
    version        = $Version
    filename       = $FinalName
    filesize       = $sizeMb
    sha256         = $hash
    signed         = $signedOk
    publisher      = $(if ($signedOk) { $sig.SignerCertificate.GetNameInfo('SimpleName', $false) } else { $null })
    download_url   = "/downloads/$FinalName"
    virustotal_url = "https://www.virustotal.com/gui/file/$hash"
    released       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json -Depth 4 | Out-File -FilePath $Manifest -Encoding utf8

if ($sign) { Remove-Item $MetaFile -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host "  Installer : $FinalExe"
Write-Host "  Size      : $sizeMb"
Write-Host "  SHA-256   : $hash"
Write-Host "  Signed    : $signedOk $(if ($signedOk) { '(' + $sig.SignerCertificate.Subject + ')' })"
Write-Host "  Manifest  : $Manifest"
Write-Host ""
Write-Host "Next: upload $FinalName to VirusTotal BEFORE publishing, then copy" -ForegroundColor Cyan
Write-Host "      downloads\* to the server's /downloads/ folder." -ForegroundColor Cyan
