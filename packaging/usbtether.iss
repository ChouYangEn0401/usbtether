; Inno Setup script for the usbtether desktop app. Built by packaging/build.ps1, which passes
; AppVersion and SourceDir (the PyInstaller output folder). Per-user install: no admin needed.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\build\dist\usbtether"
#endif

[Setup]
AppId={{6F0E4C7A-3B51-4C2E-9E58-6A1D2C7B9F21}
AppName=usbtether
AppVersion={#AppVersion}
AppPublisher=usbtether contributors
DefaultDirName={localappdata}\Programs\usbtether
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\build\installer
OutputBaseFilename=usbtether-setup-{#AppVersion}
SetupIconFile=..\src\usbtether\usbtether.ico
UninstallDisplayIcon={app}\usbtether.exe
UninstallDisplayName=usbtether
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesAssociations=yes
CloseApplications=force
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"
Name: "startup"; Description: "Start usbtether when I sign in (waits for the USB drive in the background)"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{autoprograms}\usbtether"; Filename: "{app}\usbtether.exe"
Name: "{autodesktop}\usbtether"; Filename: "{app}\usbtether.exe"; Tasks: desktopicon

[Registry]
; Double-clicking *.utenc runs "usbtether.exe open <file>" (same keys as `usbtether register`).
Root: HKCU; Subkey: "Software\Classes\.utenc"; ValueType: string; ValueName: ""; ValueData: "usbtether.encfile"; Flags: uninsdeletevalue uninsdeletekeyifempty
Root: HKCU; Subkey: "Software\Classes\usbtether.encfile"; ValueType: string; ValueName: ""; ValueData: "usbtether encrypted file"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\usbtether.encfile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\usbtether.exe,0"
Root: HKCU; Subkey: "Software\Classes\usbtether.encfile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\usbtether.exe"" open ""%1"""
; Start at sign-in (the panel's "Start with Windows" switch uses the same value).
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "usbtether"; ValueData: """{app}\usbtether.exe"" app --minimized"; Flags: uninsdeletevalue; Tasks: startup

[Run]
Filename: "{app}\usbtether.exe"; Description: "Open the usbtether panel now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop the panel and any open-file helpers so their files can be removed.
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM usbtether.exe"; Flags: runhidden; RunOnceId: "StopUsbtether"

[UninstallDelete]
; Leftover working copies only. registry.json, bound folders and secrets in %APPDATA%\usbtether
; are kept on purpose: deleting them would make encrypted files unopenable.
Type: filesandordirs; Name: "{userappdata}\usbtether\open"
