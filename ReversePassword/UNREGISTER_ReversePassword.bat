:: Fix issue with "Run as Administrator" current dir
cd /d "%~dp0"

regsvr32.exe /u /s ReversePassword.comhost.dll

reg.exe import uninstall.reg
