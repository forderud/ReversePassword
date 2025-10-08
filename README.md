| Project | Description |
|---------|-------------|
| [**ReversePassword**](ReversePassword/) | Sample Windows Credential Provider that require the password to by typed backwards. Written in C#. |
| [**NoPasswordAuthPkg**](NoPasswordAuthPkg/) | Sample authentication package to allow interactive logon without having to type the password. |

## How to test
It's recommended to **test in a disposable Virtual Machine (VM)**, since credential provider problems might break the windows logon screen. You don't want to risk that on your main computer.

#### Build steps
* Open solution in Visual Studio and build the projects in release or debug mode.

#### Installation steps
* Install [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/en-us/download/dotnet)
* Copy the build artifacts to the test environment.
* Run `REGISTER_ReversePassword.bat` as administrator.
* Log screen, log out or restart the computer.
* Observe that there's now a new "RP" sign-in option:  
![screenshot](Screenshot.png)  

* `CredUITester.exe` can also be used for testing the credential provider:  
![CredUIPrompt](CredUIPrompt.png)  

Password entering can be avoided altogether if NoPasswordAuthPkg is also installed. This can be done by running `Install_NoPasswordAuthPkg.bat` as administrator and restarting afterwards.

#### Uninstallation steps
* Right click on `UNREGISTER_ReversePassword.bat` and select "Run as administrator".


## Authentication and logon documentation

#### User session and authentication
* Show authentication dialog: [CredUIPromptForWindowsCredentials](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creduipromptforwindowscredentialsw)
* Logoff, shutdown or restart:  [ExitWindowsEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-exitwindowsex) with `EWX_LOGOFF`, `EWX_POWEROFF` or `EWX_REBOOT` parameter.
* Lock desktop: [LockWorkStation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-lockworkstation) (same as Ctrl+Alt+Del and click "Lock")
* Authenticate to impersonate a user: [LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw)

#### Credential provider
* [Credential providers in Windows](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
* [Credential Provider driven Windows Logon Experience](https://github.com/user-attachments/files/22509252/Credential_Provider_Technical_Reference.pdf) (converted https://go.microsoft.com/fwlink/?LinkId=717287 from XPS to PDF)
* Windows-classic-samples [CredentialProvider](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/CredentialProvider)
* Win7Samples [credentialproviders](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Win7Samples/security/credentialproviders)

The project is heavily based on the no longer maintained [CredProvider.NET](https://github.com/SteveSyfuhs/CredProvider.NET)

#### Security and authentication packages
* [LSA Authentication Model](https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication-model)
* [Creating Custom Security Packages](https://learn.microsoft.com/en-us/windows/win32/secauthn/creating-custom-security-packages)
* [MSV1_0 Authentication Package](https://learn.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) is used for local machine logons (Kerberos is used for network logons).
