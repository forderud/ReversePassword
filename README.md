Example Windows Credential Provider that require your password to by typed backwards. Written in C#.

## How to test
It's recommended to **test in a disposable Virtual Machine (VM)**, since credential provider problems might break the windows logon screen. You don't want to risk that on your main computer.

Build steps:
* Open solution in Visual Studio and build in release or debug mode.
* Copy `install.reg`, `uninstall.reg`, `REGISTER.bat` and `UNREGISTER.bat` into the same folder as the generated `ReversePassword.comhost.dll`.

Installation steps:
* Install [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/en-us/download/dotnet)
* Right click on `REGISTER.bat` and select "Run as administrator".
* Log screen, log out or restart the computer.
* Observe that there's now a new "RP" sign-in option.

![screenshot](Screenshot.png)  

NOTE: You might need to run `CredUITester.exe` with admin privileges if not installed to a folder where all users have read access.

Uninstallation steps:
* Right click on `UNREGISTER.bat` and select "Run as administrator".


## Authentication and logon APIs
![CredUIPrompt](CredUIPrompt.png)  

#### Relevant Win32 APIs
* Show authentication dialog: [CredUIPromptForWindowsCredentials](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-creduipromptforwindowscredentialsw)
* Logoff, shutdown or restart:  [ExitWindowsEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-exitwindowsex) with `EWX_LOGOFF`, `EWX_POWEROFF` or `EWX_REBOOT` parameter.
* Lock desktop: [LockWorkStation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-lockworkstation) (same as Ctrl+Alt+Del and click "Lock")
* Authenticate to impersonate a user: [LogonUserW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw)


## External links
* [Credential providers in Windows](https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-providers-in-windows)
* The project is heavily based on the no longer maintained [CredProvider.NET](https://github.com/SteveSyfuhs/CredProvider.NET).
