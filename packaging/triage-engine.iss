; Inno Setup definition. The source directory is supplied by build-windows.ps1.
#ifndef SourceDir
  #define SourceDir "..\dist-windows\portable\TriageEngine"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist-windows\installer"
#endif

#define AppName "Triage Engine"
#define AppVersion "3.0.0"
#define AppPublisher "Triage Engine"
#define AppExeName "TriageEngine.exe"

[Setup]
AppId={{8E5AC3F5-1C29-4F7B-8D72-6E3A1DA20D4B}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Triage Engine
DefaultGroupName={#AppName}
OutputDir={#OutputDir}
OutputBaseFilename=TriageEngine-{#AppVersion}-Setup
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
Name: "{commonappdata}\TriageEngine"
Name: "{commonappdata}\TriageEngine\data"
Name: "{commonappdata}\TriageEngine\cases"

[Icons]
Name: "{group}\Triage Engine"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\launch-triage.ps1"" -Wait -DataRoot ""{commonappdata}\TriageEngine\data"" -CasesRoot ""{commonappdata}\TriageEngine\cases"""; WorkingDir: "{app}"
Name: "{commondesktop}\Triage Engine"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\launch-triage.ps1"" -DataRoot ""{commonappdata}\TriageEngine\data"" -CasesRoot ""{commonappdata}\TriageEngine\cases"""; WorkingDir: "{app}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\launch-triage.ps1"" -DataRoot ""{commonappdata}\TriageEngine\data"" -CasesRoot ""{commonappdata}\TriageEngine\cases"""; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
; Deliberately no data/cases deletion: customer evidence must survive uninstall.
