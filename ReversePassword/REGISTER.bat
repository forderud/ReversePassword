:: Fix issue with "Run as Administrator" current dir
setlocal enableextensions
cd /d "%~dp0"

regsvr32.exe ReversePassword.comhost.dll

install.reg
