# Bluetooth subauthentication package
Sample MSV1_0 subauthentication package that **will deny login if Bluetooth is enabled** on the machine.

### Limitation
The `Msv1_0SubAuthenticationFilter` function only appear to be called _after_ the inbuilt MSV1_0 authentication package. This enables adding of extra checks, but it doesn't seem to be possible to bypass password checking performed by MSV1_0.


## Prerequisite
Local Security Authority (LSA) protection needs to be disabled in order for the autentication package DLL to load.

#### Instructions
* Open "Windows Security"
* Click on "Device security"
* Click on "Core isolation"
* Turn off "Local Security Authority protection"
* Reboot

## Installation
Run `install.bat` as admin.

## External links
* [`Msv1_0SubAuthenticationFilter`](https://learn.microsoft.com/en-us/windows/win32/api/subauth/nf-subauth-msv1_0subauthenticationfilter) user logon entry point (only called if DLL is registered as 'Auth0')
* [`Msv1_0SubAuthenticationRoutine`](https://learn.microsoft.com/en-us/windows/win32/api/subauth/nf-subauth-msv1_0subauthenticationroutine) client/server entry point
* [Registering Subauthentication Packages](https://learn.microsoft.com/en-us/previous-versions//aa379395(v=vs.85))
* [MSV1_0 SubAuthentication Sample](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Win7Samples/security/authentication/msvsubauth) shows how to extend the MSV1_0 Authentication Package
