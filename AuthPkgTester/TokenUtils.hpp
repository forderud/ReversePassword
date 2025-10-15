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
    case STATUS_ACCOUNT_RESTRICTION: return L"STATUS_ACCOUNT_RESTRICTION";
    case STATUS_LOGON_FAILURE: return L"STATUS_LOGON_FAILURE";
    default: return L"error " + std::to_wstring(err);
    }
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

/** Based on https://learn.microsoft.com/en-us/previous-versions/aa446670(v=vs.85) */
PSID GetLogonSID (HANDLE hToken) {
    std::vector<BYTE> tokenGroupsBuf;
    {
        // Get TOKEN_GROUPS size
        DWORD bufSize = 0;
        if (GetTokenInformation(hToken, TokenGroups, nullptr, 0, &bufSize))
            abort(); // call is supposed to fail
        assert(GetLastError() == ERROR_INSUFFICIENT_BUFFER);

        // Get the token group information from the access token
        tokenGroupsBuf.resize(bufSize, (BYTE)0);
        if (!GetTokenInformation(hToken, TokenGroups, (LPVOID)tokenGroupsBuf.data(), bufSize, &bufSize)) {
            abort();
        }
    }
    auto* tg = (TOKEN_GROUPS*)tokenGroupsBuf.data();

    // Loop through the groups to find the logon SID.
    for (DWORD i = 0; i < tg->GroupCount; i++) {
        if ((tg->Groups[i].Attributes & SE_GROUP_LOGON_ID) != SE_GROUP_LOGON_ID)
            continue;
        
        // Found the logon SID; make a copy of it.
        DWORD sidLength = GetLengthSid(tg->Groups[i].Sid);
        auto sid = (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sidLength); // allocator compatible with FreeSid
        if (!CopySid(sidLength, sid, tg->Groups[i].Sid))
            abort();
        return sid;
    }

    abort(); // SE_GROUP_LOGON_ID not found
}
