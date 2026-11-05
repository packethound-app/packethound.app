; PacketHound installer (Inno Setup 7). Build it with:  .\build.ps1 -Installer
; Packages the self-contained publish\installer\PacketHound.exe into publish\PacketHound-Setup-<version>.exe.

#define ExePath AddBackslash(SourcePath) + "..\publish\installer\PacketHound.exe"
#if !FileExists(ExePath)
  #error publish\installer\PacketHound.exe not found. Run .\build.ps1 -Installer instead of compiling this script directly.
#endif
#define VerMajor
#define VerMinor
#define VerRev
#define VerBuild
#expr GetVersionComponents(ExePath, VerMajor, VerMinor, VerRev, VerBuild)
#define AppVersion Str(VerMajor) + "." + Str(VerMinor) + "." + Str(VerRev)

[Setup]
; Never change AppId: Windows uses it to recognise upgrades and the uninstall entry.
AppId={{1D67EC51-F82A-4318-9704-1EAA87AD8CE7}
AppName=PacketHound
AppVersion={#AppVersion}
AppVerName=PacketHound {#AppVersion}
VersionInfoVersion={#AppVersion}
; Program Files: only admins can change the exe, which matters because the startup task runs it elevated.
DefaultDirName={autopf}\PacketHound
DisableDirPage=yes
DefaultGroupName=PacketHound
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
WizardStyle=modern dynamic
; Icons and wizard images are generated from the logo by tools\make-icons.py.
SetupIconFile=..\src\PacketHound\Assets\PacketHound.ico
WizardSmallImageFile=wizard-small-55.bmp,wizard-small-69.bmp,wizard-small-83.bmp,wizard-small-110.bmp,wizard-small-138.bmp
; 32-bit BMPs with ordinary (not premultiplied) transparency, so the badge sits cleanly on light or dark wizards.
WizardImageAlphaFormat=defined
UninstallDisplayIcon={app}\PacketHound.exe
UninstallDisplayName=PacketHound
OutputDir=..\publish
OutputBaseFilename=PacketHound-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
; Setup closes a running PacketHound itself (see PrepareToInstall), so skip Restart Manager's prompt.
CloseApplications=no
; Code signing: once you have a certificate, define a sign tool in the Inno Setup IDE
; (Tools > Configure Sign Tools), e.g. named "signtool", and uncomment the next line.
; SignTool=signtool

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Add "sign" to Flags once SignTool is set, so the app itself is signed too.
Source: "..\publish\installer\PacketHound.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\PacketHound"; Filename: "{app}\PacketHound.exe"
Name: "{autodesktop}\PacketHound"; Filename: "{app}\PacketHound.exe"; Tasks: desktopicon

[Run]
; postinstall entries run as the non-elevated user by default, and PacketHound requires admin
; (CreateProcess then fails with error 740). runascurrentuser starts it with Setup's admin rights.
Filename: "{app}\PacketHound.exe"; Description: "Start PacketHound"; Flags: nowait postinstall skipifsilent runascurrentuser

[Code]
var
  DeleteRules: Boolean;

// Upgrading: stop the running copy so its exe can be replaced. Protection stays as it was,
// and the new version picks it up when it starts.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM PacketHound.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  DeleteRules := True;
  if not UninstallSilent() then
    DeleteRules := MsgBox('Also delete the firewall rules PacketHound created?' + #13#10#13#10 +
      'Yes (recommended): apps you blocked can connect again.' + #13#10 +
      'No: the rules stay in Windows Firewall (wf.msc), and apps you blocked stay blocked.',
      mbConfirmation, MB_YESNO) = IDYES;
  Result := True;
end;

// Before the files go: put Windows Firewall back the way it was before PacketHound.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Params: String;
  ResultCode: Integer;
begin
  if CurUninstallStep <> usUninstall then exit;

  Params := '--uninstall';
  if not DeleteRules then Params := Params + ' --keep-rules';

  if Exec(ExpandConstant('{app}\PacketHound.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
     and (ResultCode = 0) then
    // Settings and log are only needed while installed. Kept on failure: they hold the original firewall settings.
    DelTree(ExpandConstant('{commonappdata}\PacketHound'), True, True, True)
  else
    SuppressibleMsgBox('PacketHound could not restore all of Windows Firewall''s settings, so apps without a rule may still be blocked.' + #13#10#13#10 +
      'To allow outgoing connections again, run this in an administrator command prompt:' + #13#10 +
      'netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound' + #13#10#13#10 +
      'Details are in ' + ExpandConstant('{commonappdata}\PacketHound\packethound.log'),
      mbError, MB_OK, IDOK);
end;
