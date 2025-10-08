# Always run script as admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$($MyInvocation.MyCommand.Path)`" -ExecutionPolicy Bypass"
    exit
}


Write-Host "Installing NoPasswordAuthPkg.dll to %SYSTEMROOT%\System32..."
Copy-Item "$PSScriptRoot\NoPasswordAuthPkg.dll" -Destination "$env:SystemRoot\System32"

Write-Host "Registering security package..."
# Add DLL to "Security Packages" list in registry
$path = "HKLM:\System\CurrentControlSet\Control\Lsa"
$name = "Security Packages"
$secPkgList = (Get-ItemProperty -Path $path).$name # REG_MULTI_SZ list
$secPkgList += "NoPasswordAuthPkg"
Set-ItemProperty -Path $path -Name $name -Value $secPkgList -Type MultiString
