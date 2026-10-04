:: Fix issue with "Run as Administrator" current dir
cd /d "%~dp0"

regsvr32.exe /s ReversePasswordCredProv.dll

regsvr32.exe /s ReversePasswordEventProv.dll
