# Builds PacketHound.exe into .\publish
#   .\build.ps1                 small exe; needs the .NET 10 Desktop Runtime on the PC
#   .\build.ps1 -SelfContained  larger exe that runs anywhere (Windows 10/11)
#   .\build.ps1 -Arch arm64     the same for Windows on ARM (default: x64); combine with -SelfContained
#   .\build.ps1 -Installer      self-contained x64 and ARM64 exes plus an installer for each (needs Inno Setup):
#                               publish\PacketHound-Setup-<version>.exe and publish\PacketHound-Setup-<version>-arm64.exe
param([switch]$SelfContained, [switch]$Installer, [ValidateSet('x64', 'arm64')][string]$Arch = 'x64')
$ErrorActionPreference = 'Stop'
if ($Installer) { $SelfContained = $true }  # people installing it shouldn't need .NET

# Prefer a per-user SDK (dotnet-install.ps1 default location), else whatever dotnet is on PATH.
$dotnet = Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe'
if (-not (Test-Path $dotnet)) { $dotnet = 'dotnet' }

function Publish([string]$arch, [string]$outDir) {
    $publishArgs = @("publish", "$PSScriptRoot\src\PacketHound\PacketHound.csproj", "-c", "Release", "-r", "win-$arch",
                     "-p:PublishSingleFile=true", "-o", $outDir)
    if ($SelfContained) {
        $publishArgs += @("--self-contained", "true", "-p:IncludeNativeLibrariesForSelfExtract=true", "-p:EnableCompressionInSingleFile=true")
    } else {
        $publishArgs += @("--self-contained", "false")
    }
    & $dotnet @publishArgs
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed ($arch)" }
    Write-Host "`nBuilt: $outDir\PacketHound.exe"
}

if (-not $Installer) {
    $outDir = if ($Arch -eq 'x64') { "$PSScriptRoot\publish" } else { "$PSScriptRoot\publish\$Arch" }
    Publish $Arch $outDir
    return
}

$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 7\ISCC.exe",
          "${env:ProgramFiles}\Inno Setup 7\ISCC.exe",
          "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
          "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup (ISCC.exe) not found. Install it from https://jrsoftware.org/isinfo.php" }

$setups = @{}
foreach ($a in 'x64', 'arm64') {
    $exe = "$PSScriptRoot\publish\installer\$a\PacketHound.exe"
    Publish $a (Split-Path $exe)
    & $iscc /Q "/DArch=$a" "$PSScriptRoot\installer\PacketHound.iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed ($a)" }
    # Same version and name the .iss derives: <major>.<minor>.<build> of the exe, plus -arm64 for ARM.
    $v = [version](Get-Item $exe).VersionInfo.FileVersion
    $suffix = if ($a -eq 'arm64') { '-arm64' } else { '' }
    $setups[$a] = Get-Item "$PSScriptRoot\publish\PacketHound-Setup-$($v.Major).$($v.Minor).$($v.Build)$suffix.exe"
    Write-Host "Installer ($a): $($setups[$a].FullName)"
}

# Ready for the website: upload website\downloads\ along with the rest of the site.
# Only x64 for now; the ARM64 installer stays in publish\ until it has been tested on an ARM PC.
$siteDownloads = "$PSScriptRoot\website\downloads"
New-Item -ItemType Directory -Force $siteDownloads | Out-Null
Copy-Item $setups['x64'].FullName $siteDownloads -Force
Write-Host "Copied to:  $siteDownloads\$($setups['x64'].Name)"
