@echo off
:: This script require the Windows ADK to be installed (https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install)


:: Create a CD-ROM ISO file based on the content of the TestISO subfolder
"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe" -j2 -l"DisablePWCheck" "TestISO" "DisablePasswordCheck.iso"
