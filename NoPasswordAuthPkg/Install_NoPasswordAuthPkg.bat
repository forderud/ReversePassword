:: Fix issue with "Run as Administrator" current dir
cd /d "%~dp0"

echo Installing authentication package DLL...

copy NoPasswordAuthPkg.dll %SYSTEMROOT%\System32


reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d NoPasswordAuthPkg\0 /f

pause
