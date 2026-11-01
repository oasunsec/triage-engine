; Inno Setup definition. The source directory is supplied by build-windows.ps1.
#ifndef SourceDir
  #define SourceDir "..\dist-windows\portable\Corrobora"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist-windows\installer"
#endif

#define AppName "Corrobora"
#define AppVersion "3.0.0"
#define AppPublisher "Corrobora"
#define AppExeName "Corrobora.exe"

[Setup]
AppId={{8E5AC3F5-1C29-4F7B-8D72-6E3A1DA20D4B}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Corrobora
DefaultGroupName={#AppName}
OutputDir={#OutputDir}
OutputBaseFilename=Corrobora-{#AppVersion}-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Uninstallable=yes
WizardStyle=modern

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
; Keep durable evidence outside {app}; these directories survive upgrade/uninstall.
Name: "{commonappdata}\Corrobora"
Name: "{commonappdata}\Corrobora\data"
Name: "{commonappdata}\Corrobora\cases"

[Icons]
Name: "{group}\Corrobora"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\launch-corrobora.ps1"" -Wait -DataRoot ""{commonappdata}\Corrobora\data"" -CasesRoot ""{commonappdata}\Corrobora\cases"""; WorkingDir: "{app}"
Name: "{commondesktop}\Corrobora"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\launch-corrobora.ps1"" -DataRoot ""{commonappdata}\Corrobora\data"" -CasesRoot ""{commonappdata}\Corrobora\cases"""; WorkingDir: "{app}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\launch-corrobora.ps1"" -DataRoot ""{commonappdata}\Corrobora\data"" -CasesRoot ""{commonappdata}\Corrobora\cases"""; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
; Deliberately no data/cases deletion: customer evidence must survive uninstall.
