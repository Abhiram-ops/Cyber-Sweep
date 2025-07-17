[Setup]
AppName=CyberSweep
AppVersion=1.0
DefaultDirName={pf}\CyberSweep
DefaultGroupName=CyberSweep
OutputDir=.
OutputBaseFilename=CyberSweep_Installer
Compression=lzma
SolidCompression=yes
SetupIconFile=C:\Users\abhir\Documents\Integrated_pentest\icon_glow.ico

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "C:\Users\abhir\Documents\Integrated_pentest\dist\csweep.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Users\abhir\Documents\Integrated_pentest\icon_glow.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\CyberSweep"; Filename: "{app}\csweep.exe"; IconFilename: "{app}\icon_glow.ico"
Name: "{group}\Uninstall CyberSweep"; Filename: "{uninstallexe}"
Name: "{commondesktop}\CyberSweep"; Filename: "{app}\csweep.exe"; Tasks: desktopicon; IconFilename: "{app}\icon_glow.ico"


[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{app}\csweep.exe"; Description: "Launch CyberSweep CLI"; Flags: nowait postinstall skipifsilent
