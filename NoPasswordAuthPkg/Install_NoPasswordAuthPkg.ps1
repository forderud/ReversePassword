# Always run script as admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$($MyInvocation.MyCommand.Path)`" -ExecutionPolicy Bypass"
    exit
}


Write-Host "Copying NoPasswordAuthPkg.dll to %SYSTEMROOT%\System32..."
Copy-Item "$PSScriptRoot\NoPasswordAuthPkg.dll" -Destination "$env:SystemRoot\System32"

Write-Host "Registering DLL as a security package..."
# Read "Security Packages" REG_MULTI_SZ list from registry
$path = "HKLM:\System\CurrentControlSet\Control\Lsa"
$name = "Security Packages"
$secPkgList = (Get-ItemProperty -Path $path).$name
# Add NoPasswordAuthPkg to list
$secPkgList += "NoPasswordAuthPkg"
# Write modified registry value back
Set-ItemProperty -Path $path -Name $name -Value $secPkgList -Type MultiString
