Command-line tool for authentication package testing and running `cmd.exe` throgh other user accounts.

Calls [`LsaLogonUser`](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser) to authenticate against a given authentication package. Afterwards, [`CreateProcessWithToken`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) is used to start `cmd.exe` through the authenticated user account.

## Open issues
* [issue #25](../../issues/25)


### Links
* Microsoft: [Starting an Interactive Client Process in C++](https://learn.microsoft.com/en-us/previous-versions/aa379608(v=vs.85))
* Microsoft: [Getting the Logon SID in C++](https://learn.microsoft.com/en-us/previous-versions/aa446670(v=vs.85))
