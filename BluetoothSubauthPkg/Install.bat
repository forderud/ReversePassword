:: Fix issue with "Run as Administrator" current dir
cd /d "%~dp0"

echo Installing authentication package DLL...

copy BluetoothSubauthPkg.dll %SYSTEMROOT%\System32

reg import install.reg

pause

