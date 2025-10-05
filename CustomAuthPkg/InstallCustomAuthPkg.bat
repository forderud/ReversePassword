:: Fix issue with "Run as Administrator" current dir
cd /d "%~dp0"

echo Installing authentication package DLL...

copy CustomAuthPkg.dll %SYSTEMROOT%\System32


reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d CustomAuthPkg\0 /f

pause
