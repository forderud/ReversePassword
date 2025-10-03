# Bluetooth subauthentication package
Sample MSV1_0 subauthentication package that will deny login if Bluetooth is enabled on the machine.


## Disable LSA protection
Local Security Authority (LSA) protection needs to be disabled in order for the autentication package DLL to load.

Instructions:
* Open "Windows Security"
* Click on "Device security"
* Click on "Core isolation"
* Turn off "Local Security Authority protection"

## Installation
Run `install.bat` as admin.

## External links
* [Registering Subauthentication Packages](https://learn.microsoft.com/en-us/previous-versions//aa379395(v=vs.85))
* [Msv1_0SubAuthenticationFilter](https://learn.microsoft.com/en-us/windows/win32/api/subauth/nf-subauth-msv1_0subauthenticationfilter) user logon entry point (only called if DLL is registered as 'Auth0')
* [Msv1_0SubAuthenticationRoutine](https://learn.microsoft.com/en-us/windows/win32/api/subauth/nf-subauth-msv1_0subauthenticationroutine) client/server entry point
* [MSV1_0 SubAuthentication Sample](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Win7Samples/security/authentication/msvsubauth) shows how to extend the MSV1_0 Authentication Package
