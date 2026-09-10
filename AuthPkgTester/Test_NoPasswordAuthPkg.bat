@echo off
:: Fix issue with "Run as Administrator" current dir
cd /d "%~dp0"

echo NOTICE: Script must run from an admin command-prompt.

AuthPkgTester.exe NoPasswordAuthPkg TestUser IncorrectPassword

pause
