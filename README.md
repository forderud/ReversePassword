# ReversePassword
A Windows Credential Provider that require the password to by typed backwards. It's written in C#.

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

## Background
The project is heavily based on the no longer maintained [CredProvider.NET](https://github.com/SteveSyfuhs/CredProvider.NET).

