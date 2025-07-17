[Setup]
AppName=CyberSweep
AppVersion=1.0
DefaultDirName={pf}\CyberSweep
DefaultGroupName=CyberSweep
OutputBaseFilename=csweep_installer
OutputDir=C:\Users\abhir\Documents\Integrated_pentest\dist
SetupIconFile=C:\Users\abhir\Documents\Integrated_pentest\icon_glow.ico
Compression=lzma
SolidCompression=yes

[Files]
Source: "C:\Users\abhir\Documents\Integrated_pentest\dist\csweep.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Users\abhir\Documents\Integrated_pentest\main.py"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\CyberSweep"; Filename: "{app}\csweep.exe"; IconFilename: "{app}\icon_glow.ico"
Name: "{commondesktop}\CyberSweep"; Filename: "{app}\csweep.exe"; IconFilename: "{app}\icon_glow.ico"
