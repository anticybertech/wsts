; ── WSTS — Windows Security Threat Scanner — Inno Setup installer ───────────
; Wraps the PyInstaller folder build (dist\WSTS) into WSTS-Setup-<version>.exe.
; Built and signed by build_wsts.ps1; compile manually with:
;   ISCC.exe /DAppVersion=1.0.1 wsts.iss
;
; Requires Inno Setup 6 (https://jrsoftware.org/isinfo.php).

#ifndef AppVersion
  #define AppVersion "1.0.1"
#endif
#define AppName      "WSTS - Windows Security Threat Scanner"
#define AppShortName "WSTS"
#define AppPublisher "Antibody Cyber Technology, LLC"
#define AppURL       "https://wincyberscan.com/"

[Setup]
AppId={{8F6C2A1E-5B7D-4C3A-9E21-7A4D0B6E9C15}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}user-guide.html
AppUpdatesURL={#AppURL}
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup
VersionInfoCopyright=(c) 2026 {#AppPublisher}
DefaultDirName={autopf}\Antibody Cyber\WSTS
DefaultGroupName=WSTS
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=downloads
OutputBaseFilename=WSTS-Setup-{#AppVersion}
SetupIconFile=static\img\wsts.ico
UninstallDisplayIcon={app}\WSTS.exe
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Signing is done by build_wsts.ps1 after compilation (Artifact Signing).

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "dist\WSTS\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\WSTS - Windows Security Threat Scanner"; Filename: "{app}\WSTS.exe"
Name: "{group}\WSTS User Guide"; Filename: "{#AppURL}user-guide.html"
Name: "{group}\Uninstall WSTS"; Filename: "{uninstallexe}"
Name: "{autodesktop}\WSTS"; Filename: "{app}\WSTS.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\WSTS.exe"; Description: "Launch WSTS now"; Flags: nowait postinstall skipifsilent shellexec

[UninstallDelete]
; Session file WSTS writes for single-instance detection (per user).
Type: filesandordirs; Name: "{localappdata}\WSTS"
