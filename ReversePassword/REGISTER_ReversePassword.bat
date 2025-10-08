:: Fix issue with "Run as Administrator" current dir
cd /d "%~dp0"

regsvr32.exe /s ReversePassword.comhost.dll

reg.exe import install.reg
