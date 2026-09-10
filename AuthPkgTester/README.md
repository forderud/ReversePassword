Command-line tool for authentication package testing and running `cmd.exe` throgh other user accounts.

#### Usage
* List installed security packages: `AuthPkgTester.exe`
* Local account authentication: `AuthPkgTester.exe <authPkgName> <usename> <password>`
* Network account authentication: `AuthPkgTester.exe <authPkgName> <domain>\<usename> <password>`

The `<authPkgName>` argument is optional and will default to MSV1_0.

#### Preinstalled authentication packages
* [`MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`](https://learn.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) (MSV1_0): For _local_ logons
* [`Negotiate`](https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-negotiate): Automatically selects Kerberos or NTLM for _network_ logon
* ~~[`Kerberos`](https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-kerberos): For logging on to a _network_ (don't access directly)~~
* ~~[`NTLM`](https://learn.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm): Authentication protocol used on _networks_ (don't access directly)~~


### API alternative overview
| API | Privileges required | Desktop/window station | UI theme |
|-----|----------------|----------------------------|--------------|
| [`CreateProcessWithLogon`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) (incompatible with authentication packages) | Admin privileges | Works automatically | Applied |
| [`CreateProcessWithToken`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) | Admin privileges | Need to grant access manually | Not applied |
| [`CreateProcessAsUser`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw) | `SE_INCREASE_QUOTA_NAME` and `SE_ASSIGNPRIMARYTOKEN_NAME` (grant with `PsExec.exe -i -s cmd.exe`) | Need to grant access manually | Not applied |

Doc quote:
> you must change the discretionary access control list (DACL) of both the default interactive window station and the default desktop. The DACLs for the window station and desktop must grant access to the user or the logon session represented by the hToken parameter.

### Implementation details
* [`LsaLogonUser`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser) is used to authenticate against a given authentication package.
* The logon session ID ([`SE_GROUP_LOGON_ID`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_groups)) is granted access to the window station and desktop.
* [`CreateProcessWithToken`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) is used to start `cmd.exe` under the authenticated user account.

### Open issues
* [issue #25](../../../issues/25) UI theme settings not applied

### Related projects
* Win32 [runas](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525(v=ws.11)) tool (doesn't support custom authentication packages)
* [antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs) (issue: https://github.com/antonioCoco/RunasCs/issues/20)
* [JetBrains.runAs](https://github.com/JetBrains/runAs) (issue: https://github.com/JetBrains/runAs/issues/9)

### Links
* Microsoft: [Starting an Interactive Client Process in C++](https://learn.microsoft.com/en-us/previous-versions/aa379608(v=vs.85))
* Microsoft: [Getting the Logon SID in C++](https://learn.microsoft.com/en-us/previous-versions/aa446670(v=vs.85))
