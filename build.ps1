# Builds PacketHound.exe into .\publish
#   .\build.ps1                 small exe; needs the .NET 10 Desktop Runtime on the PC
#   .\build.ps1 -SelfContained  larger exe that runs anywhere (Windows 10/11 x64)
#   .\build.ps1 -Installer      self-contained exe plus publish\PacketHound-Setup-<version>.exe (needs Inno Setup)
param([switch]$SelfContained, [switch]$Installer)
$ErrorActionPreference = 'Stop'
if ($Installer) { $SelfContained = $true }  # people installing it shouldn't need .NET

# Prefer a per-user SDK (dotnet-install.ps1 default location), else whatever dotnet is on PATH.
$dotnet = Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe'
if (-not (Test-Path $dotnet)) { $dotnet = 'dotnet' }

$outDir = if ($Installer) { "$PSScriptRoot\publish\installer" } else { "$PSScriptRoot\publish" }
$publishArgs = @("publish", "$PSScriptRoot\src\PacketHound\PacketHound.csproj", "-c", "Release", "-r", "win-x64",
                 "-p:PublishSingleFile=true", "-o", $outDir)
if ($SelfContained) {
    $publishArgs += @("--self-contained", "true", "-p:IncludeNativeLibrariesForSelfExtract=true", "-p:EnableCompressionInSingleFile=true")
} else {
    $publishArgs += @("--self-contained", "false")
}
& $dotnet @publishArgs
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }
Write-Host "`nBuilt: $outDir\PacketHound.exe"

if ($Installer) {
    $iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 7\ISCC.exe",
              "${env:ProgramFiles}\Inno Setup 7\ISCC.exe",
              "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
              "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) { throw "Inno Setup (ISCC.exe) not found. Install it from https://jrsoftware.org/isinfo.php" }
    & $iscc /Q "$PSScriptRoot\installer\PacketHound.iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }
    $setup = Get-ChildItem "$PSScriptRoot\publish\PacketHound-Setup-*.exe" | Sort-Object LastWriteTime | Select-Object -Last 1
    Write-Host "Installer: $($setup.FullName)"

    # Ready for the website: upload website\downloads\ along with the rest of the site.
    $siteDownloads = "$PSScriptRoot\website\downloads"
    New-Item -ItemType Directory -Force $siteDownloads | Out-Null
    Copy-Item $setup.FullName $siteDownloads -Force
    Write-Host "Copied to:  $siteDownloads\$($setup.Name)"
}
