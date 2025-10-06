:: Fix issue with "Run as Administrator" current dir
cd /d "%~dp0"

echo Installing authentication package DLL...

copy NoPasswordAuthPkg.dll %SYSTEMROOT%\System32

:: TODO: Update script to append instead of overwrite the security package list
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d NoPasswordAuthPkg\0 /f

pause
