# Authentication Package (SSP/AP) sample
Minimal Security Support Provider/Authentication Package (SSP/AP) sample project that bypasses the need for entering passwords for _interactive_ logons.

### Security warning
This is a sample project that demostrates how Windows LSA athentication can be customized with authentication packages. **Do _not_ use the project as-is in production, since it will undermine security by allowing anyone to log in without passwords!** Intstead, use the project as a starting point for developing authentication packages that relies on secure sources of identity, such as biometrics, HW authentication devices, online authentication or similar.

## Prerequisite
Local Security Authority (LSA) protection needs to be disabled in order for the DLL to load.

#### Instructions
* Open "Windows Security"
* Click on "Device security"
* Click on "Core isolation"
* Turn off "Local Security Authority protection"
* Reboot

## Installation
Run `Install_NoPasswordAuthPkg.bat` as admin.

## External links
* [Registering SSP/AP DLLs](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls) 
* [LSA Mode Initialization](https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-mode-initialization)
* [SpLsaModeInitialize](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-splsamodeinitializefn) entry point
* [SECPKG_FUNCTION_TABLE](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/ns-ntsecpkg-secpkg_function_table) function dispatch table
* [Functions Implemented by Authentication Packages](https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-functions#functions-implemented-by-authentication-packages)
