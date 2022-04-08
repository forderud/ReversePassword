:: Fix issue with "Run as Administrator" current dir
setlocal enableextensions
cd /d "%~dp0"

set PATH=%PATH%;C:\Windows\Microsoft.NET\Framework64\v4.0.30319

regasm /codebase /unregister ReversePassword.dll

uninstall.reg
