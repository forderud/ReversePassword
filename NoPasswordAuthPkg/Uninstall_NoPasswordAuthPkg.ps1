# Always run script as admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$($MyInvocation.MyCommand.Path)`" -ExecutionPolicy Bypass"
    exit
}


Write-Host "Unregistering security package..."
# Remove DLL from "Security Packages" list in registry
$path = "HKLM:\System\CurrentControlSet\Control\Lsa"
$name = "Security Packages"
$secPkgList = (Get-ItemProperty -Path $path).$name
$secPkgList = $secPkgList | Where-Object {$_ -ne "NoPasswordAuthPkg"}
Set-ItemProperty -Path $path -Name $name -Value $secPkgList -Type MultiString

Write-Host "Scheduling NoPasswordAuthPkg.dll to be deleted on next reboot..."
$Win32 = Add-Type -Passthru -Name Win32 -MemberDefinition '
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);'
$Win32::MoveFileEx("$env:SystemRoot\System32\NoPasswordAuthPkg.dll", [NullString]::Value, 4 <# DelayUntilReboot #> )
