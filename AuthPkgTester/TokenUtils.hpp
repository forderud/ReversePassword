#pragma once
#include <Windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <string>
#include <vector>


const std::wstring ToString(DWORD err) {
    switch (err) {
    case ERROR_ACCESS_DENIED: return L"ERROR_ACCESS_DENIED";
    case ERROR_INVALID_HANDLE: return L"ERROR_INVALID_HANDLE";
    case ERROR_INVALID_PARAMETER: return L"ERROR_INVALID_PARAMETER";
    case ERROR_PRIVILEGE_NOT_HELD: return L"ERROR_PRIVILEGE_NOT_HELD";
    case ERROR_LOGON_FAILURE: return L"ERROR_LOGON_FAILURE user name or password incorrect";
    case ERROR_TOKEN_ALREADY_IN_USE: return L"ERROR_TOKEN_ALREADY_IN_USE";
    case ERROR_INVALID_SECURITY_DESCR: return L"ERROR_INVALID_SECURITY_DESCR";
    case ERROR_LOGON_TYPE_NOT_GRANTED: return L"ERROR_LOGON_TYPE_NOT_GRANTED";
    case STATUS_ACCESS_DENIED: return L"STATUS_ACCESS_DENIED";
    default: return L"error " + std::to_wstring(err);
    }
}

struct Privilege {
    enum State {
        Missing,
        Enabled,
        Disabled,
    };

    const wchar_t* ToString() const {
        switch (state) {
        case Missing: return L"missing";
        case Enabled: return L"enabled";
        case Disabled: return L"disabled";
        default:
            abort();
        }
    }

    Privilege(HANDLE token, const wchar_t* privName) : token(token) {
        BOOL ok = LookupPrivilegeValueW(nullptr, privName, &value);
        assert(ok);

        // detect if privilege is enabled
        std::vector<BYTE> privilegesBuffer(1024, (BYTE)0);
        {
            DWORD privilegesLength = 0;
            ok = GetTokenInformation(token, TokenPrivileges, privilegesBuffer.data(), (DWORD)privilegesBuffer.size(), &privilegesLength);
            assert(ok);
            privilegesBuffer.resize(privilegesLength);
        }
        auto* tp = (TOKEN_PRIVILEGES*)privilegesBuffer.data();

        //wprintf(L"  Privilege count: %u.\n", tp->PrivilegeCount);
        for (size_t i = 0; i < tp->PrivilegeCount; i++) {
            const LUID_AND_ATTRIBUTES entry = tp->Privileges[i];
            bool match = (value.LowPart == entry.Luid.LowPart) && (value.HighPart == entry.Luid.HighPart);
            if (!match)
                continue;

            if (entry.Attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT))
                state = Enabled;
            else
                state = Disabled;
        }
    }

    void Modify(State s) {
        // https://learn.microsoft.com/nb-no/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
        TOKEN_PRIVILEGES tp = {
            .PrivilegeCount = 1,
        };
        tp.Privileges[0] = {
            .Luid = value,
            .Attributes = (s == Enabled) ? (DWORD)SE_PRIVILEGE_ENABLED : 0,
        };

        if (!AdjustTokenPrivileges(token, /*disableAll*/false, &tp, 0, nullptr, nullptr)) {
            DWORD err = GetLastError();
            wprintf(L"ERROR: AdjustTokenPrivileges failed (%s)\n", ::ToString(err).c_str());
            abort();
        }

        state = s;
    }

private:
    HANDLE token = 0;
public:
    LUID  value{};
    State state = Missing;
};

bool AdjustTokenPrivileges(HANDLE token) {
    {
        TOKEN_TYPE tokenType = {};
        DWORD tokenLen = 0;
        if (!GetTokenInformation(token, TokenType, &tokenType, sizeof(tokenType), &tokenLen))
            abort();

        wprintf(L"  TokenType: %s\n", (tokenType == TokenPrimary) ? L"Primary" : L"Impersonation");
    }

    Privilege Impersonate(token, SE_IMPERSONATE_NAME);     // required by CreateProcessWithToken
    Privilege Security(token, SE_SECURITY_NAME);           // required to get or set the SACL

    wprintf(L"  SE_IMPERSONATE_NAME privilege %s\n", Impersonate.ToString());
    wprintf(L"  SE_SECURITY_NAME privilege %s\n", Security.ToString());

    // enable disabled privileges
    if (Impersonate.state == Privilege::Disabled) {
        wprintf(L"  Enabling SE_IMPERSONATE_NAME...\n");
        Impersonate.Modify(Privilege::Enabled);
    }
    if (Security.state == Privilege::Disabled) {
        wprintf(L"  Enabling SE_SECURITY_NAME...\n");
        Security.Modify(Privilege::Enabled);
    }

    return true;
}

/** Add a DACL entry to the window station or desktop security descriptor.
    Use BuildExplicitAccessWithNameW to initialize the "ea" argument. */
void AddWindowDaclRight(HANDLE ws, EXPLICIT_ACCESS_W& ea) {
    PSID owner = nullptr;
    PSID group = nullptr;
    ACL* dacl = nullptr;
    ACL* sacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    DWORD ret = GetSecurityInfo(ws, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, &owner, &group, &dacl, &sacl, &sd);
    assert(ret == ERROR_SUCCESS);

    ACL* newDacl = nullptr;
    ret = SetEntriesInAclW(1, &ea, /*oldAcl*/dacl, &newDacl);
    assert(ret == ERROR_SUCCESS);

    ret = SetSecurityInfo(ws, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, owner, group, newDacl, sacl);
    assert(ret == ERROR_SUCCESS);

    LocalFree(newDacl);
    LocalFree(sd);
}


/** Add a DACL entry to the token security descriptor.
    Use BuildExplicitAccessWithNameW to initialize the "ea" argument. */
bool AddTokenDaclRight(HANDLE token, EXPLICIT_ACCESS_W& ea) {
    std::vector<BYTE> relSdBuf;
    SECURITY_DESCRIPTOR* relSd = nullptr;
    {
        DWORD sdSize = 0;
        BOOL ok = GetKernelObjectSecurity(token, DACL_SECURITY_INFORMATION, nullptr, 0, &sdSize);
        assert(!ok);
        relSdBuf.resize(sdSize, (BYTE)0);
        relSd = (SECURITY_DESCRIPTOR*)relSdBuf.data();

        ok = GetKernelObjectSecurity(token, DACL_SECURITY_INFORMATION, relSdBuf.data(), (DWORD)relSdBuf.size(), &sdSize);
        assert(ok);

        assert(relSd->Control & SE_SELF_RELATIVE); // security descriptor is self-relative
    }

    std::vector<BYTE> absSdBuf;
    std::vector<BYTE> daclBuf;
    std::vector<BYTE> saclBuf;
    std::vector<BYTE> ownerBuf;
    std::vector<BYTE> primGrpBuf;
    SECURITY_DESCRIPTOR* absSd = nullptr;
    {
        // convert self-relative security descriptor to absolute
        DWORD absSdSize = 0;
        DWORD daclSize = 0;
        DWORD saclSize = 0;
        DWORD ownerSize = 0;
        DWORD primGrpSize = 0;
        BOOL ok = MakeAbsoluteSD(relSd, nullptr, &absSdSize, nullptr, &daclSize, nullptr, &saclSize, nullptr, &ownerSize, nullptr, &primGrpSize);
        assert(!ok);

        absSdBuf.resize(absSdSize, (BYTE)0);
        absSd = (SECURITY_DESCRIPTOR*)absSdBuf.data();
        daclBuf.resize(daclSize, (BYTE)0);
        saclBuf.resize(saclSize, (BYTE)0);
        ownerBuf.resize(saclSize, (BYTE)0);
        primGrpBuf.resize(saclSize, (BYTE)0);
        ok = MakeAbsoluteSD(relSd, absSd, &absSdSize, (ACL*)daclBuf.data(), &daclSize, (ACL*)saclBuf.data(), &saclSize, (PSID)ownerBuf.data(), &ownerSize, (PSID)primGrpBuf.data(), &primGrpSize);
        assert(ok);
    }

    {
        BOOL daclPresent = false;
        ACL* dacl = nullptr; // weak ptr.
        BOOL daclDefaulted = false;
        BOOL ok = GetSecurityDescriptorDacl(absSd, &daclPresent, &dacl, &daclDefaulted);
        assert(ok);

        ACL* newDacl = nullptr;
        DWORD ret = SetEntriesInAclW(1, &ea, /*oldAcl*/dacl, &newDacl);
        assert(ret == ERROR_SUCCESS);

        // replace DACL (SD must be in absolute format)
        ok = SetSecurityDescriptorDacl(absSd, daclPresent, newDacl, daclDefaulted);
        if (!ok) {
            DWORD err = GetLastError();
            wprintf(L"ERROR: SetEntriesInAclW failed (%s)\n", ToString(err).c_str());
            abort();
        }

        // update security settings
        ok = SetKernelObjectSecurity(token, DACL_SECURITY_INFORMATION, absSd);
        assert(ok);

        LocalFree(newDacl);
    }

    return true;
}


/** Grant "logonSid" access to the current window station and desktop. */
void GrantWindowStationDesktopAccess(PSID logonSid) {
    {
        // https://learn.microsoft.com/en-us/windows/win32/winstation/window-station-security-and-access-rights
        HWINSTA ws = OpenWindowStationW(L"winsta0", /*inherit*/false, READ_CONTROL | WRITE_DAC);
        assert(ws);
        {
            // Grant GENERIC_ALL to "logonSid" which grants:
            //   STANDARD_RIGHTS_REQUIRED WINSTA_ACCESSCLIPBOARD WINSTA_ACCESSGLOBALATOMS WINSTA_CREATEDESKTOP WINSTA_ENUMDESKTOPS
            //   WINSTA_ENUMERATE WINSTA_EXITWINDOWS WINSTA_READATTRIBUTES WINSTA_READSCREEN WINSTA_WRITEATTRIBUTES
            EXPLICIT_ACCESS_W ea{
                .grfAccessPermissions = GENERIC_ALL,
                .grfAccessMode = GRANT_ACCESS,
                .grfInheritance = false,
            };
            ea.Trustee = {
                .pMultipleTrustee = NULL,
                .MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE,
                .TrusteeForm = TRUSTEE_IS_SID,
                .TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP,
                .ptstrName = (wchar_t*)logonSid,
            };
            AddWindowDaclRight(ws, ea);
        }
        CloseWindowStation(ws);
    }
    {
        // https://learn.microsoft.com/en-us/windows/win32/winstation/desktop-security-and-access-rights
        HDESK desk = OpenDesktopW(L"default", 0, /*inherit*/false, READ_CONTROL | WRITE_DAC);
        assert(desk);
        {
            // Grant GENERIC_ALL to "logonSid" which grants:
            //   DESKTOP_CREATEMENU DESKTOP_CREATEWINDOW DESKTOP_ENUMERATE DESKTOP_HOOKCONTROL DESKTOP_JOURNALPLAYBACK
            //   DESKTOP_JOURNALRECORD DESKTOP_READOBJECTS DESKTOP_SWITCHDESKTOP DESKTOP_WRITEOBJECTS STANDARD_RIGHTS_REQUIRED
            EXPLICIT_ACCESS_W ea{
                .grfAccessPermissions = GENERIC_ALL,
                .grfAccessMode = GRANT_ACCESS,
                .grfInheritance = false,
            };
            ea.Trustee = {
                .pMultipleTrustee = NULL,
                .MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE,
                .TrusteeForm = TRUSTEE_IS_SID,
                .TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP,
                .ptstrName = (wchar_t*)logonSid,
            };
            AddWindowDaclRight(desk, ea);
        }
        CloseDesktop(desk);
    }
}

/** From https://learn.microsoft.com/en-us/previous-versions/aa446670(v=vs.85) */
BOOL GetLogonSID (HANDLE hToken, PSID* ppsid) {
    BOOL bSuccess = FALSE;
    DWORD dwIndex;
    DWORD dwLength = 0;
    PTOKEN_GROUPS ptg = NULL;

    // Verify the parameter passed in is not NULL.
    if (NULL == ppsid)
        goto Cleanup;

    // Get required buffer size and allocate the TOKEN_GROUPS buffer.
    if (!GetTokenInformation(
        hToken,         // handle to the access token
        TokenGroups,    // get information about the token's groups 
        (LPVOID)ptg,   // pointer to TOKEN_GROUPS buffer
        0,              // size of buffer
        &dwLength       // receives required buffer size
    )) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            goto Cleanup;

        ptg = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(),
            HEAP_ZERO_MEMORY, dwLength);

        if (ptg == NULL)
            goto Cleanup;
    }

    // Get the token group information from the access token.
    if (!GetTokenInformation(
        hToken,         // handle to the access token
        TokenGroups,    // get information about the token's groups 
        (LPVOID)ptg,   // pointer to TOKEN_GROUPS buffer
        dwLength,       // size of buffer
        &dwLength       // receives required buffer size
    )) {
        goto Cleanup;
    }

    // Loop through the groups to find the logon SID.
    for (dwIndex = 0; dwIndex < ptg->GroupCount; dwIndex++) {
        if ((ptg->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID) {
            // Found the logon SID; make a copy of it.
            dwLength = GetLengthSid(ptg->Groups[dwIndex].Sid);
            *ppsid = (PSID)HeapAlloc(GetProcessHeap(),
                HEAP_ZERO_MEMORY, dwLength);
            if (*ppsid == NULL)
                goto Cleanup;
            if (!CopySid(dwLength, *ppsid, ptg->Groups[dwIndex].Sid))
            {
                HeapFree(GetProcessHeap(), 0, (LPVOID)*ppsid);
                goto Cleanup;
            }
            break;
        }
    }

    bSuccess = TRUE;

Cleanup:
    if (ptg)
        HeapFree(GetProcessHeap(), 0, (LPVOID)ptg);

    return bSuccess;
}
