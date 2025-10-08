# Installing and registering NoPasswordAuthPkg.dll

Write-Host "Copying NoPasswordAuthPkg.dll to %SYSTEMROOT%\System32..."
copy "$PSScriptRoot\NoPasswordAuthPkg.dll" "$env:SystemRoot\System32"

Write-Host "Registering DLL as a security Package..."
# Read "Security Packages" REG_MULTI_SZ list from registry
$path = "HKLM:\System\CurrentControlSet\Control\Lsa"
$name = "Security Packages"
$secPkgList = (Get-ItemProperty -Path $path).$name

# Add NoPasswordAuthPkg to list
$secPkgList += "NoPasswordAuthPkg"

# Write modified registry value back
Set-ItemProperty -Path $path -Name $name -Value $secPkgList -Type MultiString
