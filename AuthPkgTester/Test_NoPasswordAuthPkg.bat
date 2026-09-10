:: Fix issue with "Run as Administrator" current dir
cd /d "%~dp0"

AuthPkgTester.exe NoPasswordAuthPkg TestUser IncorrectPassword

pause
