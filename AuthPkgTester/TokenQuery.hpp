#pragma once
#include <Windows.h>
#include <aclapi.h>
#include <stdio.h>


const std::wstring ToString(DWORD err) {
    switch (err) {
    case ERROR_ACCESS_DENIED: return L"ERROR_ACCESS_DENIED";
    case ERROR_INVALID_HANDLE: return L"ERROR_INVALID_HANDLE";
    case ERROR_INVALID_PARAMETER: return L"ERROR_INVALID_PARAMETER";
    case ERROR_PRIVILEGE_NOT_HELD: return L"ERROR_PRIVILEGE_NOT_HELD";
    case ERROR_TOKEN_ALREADY_IN_USE: return L"ERROR_TOKEN_ALREADY_IN_USE";
    case ERROR_INVALID_SECURITY_DESCR: return L"ERROR_INVALID_SECURITY_DESCR";
    case ERROR_LOGON_TYPE_NOT_GRANTED: return L"ERROR_LOGON_TYPE_NOT_GRANTED";
    default: return L"error " + std::to_wstring(err);
    }
}

enum class PrivilegeState {
    Missing,
    Enabled,
    Disabled,
};

const wchar_t* ToString(PrivilegeState ps) {
    switch (ps) {
    case PrivilegeState::Missing: return L"missing";
    case PrivilegeState::Enabled: return L"enabled";
    case PrivilegeState::Disabled: return L"disabled";
    default:
        abort();
    }
}

inline bool EqualLUID(LUID a, LUID b) {
    return (a.LowPart == b.LowPart) && (a.HighPart == b.HighPart);
}

void CheckPrivilegeEnabled(LUID_AND_ATTRIBUTES entry, LUID priv, /*out*/PrivilegeState& state) {
    if (!EqualLUID(entry.Luid, priv))
        return;

    if (entry.Attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT))
        state = PrivilegeState::Enabled;
    else
        state = PrivilegeState::Disabled;
}


bool CheckTokenPrivileges(HANDLE token, bool enableDisabled) {
    {
        TOKEN_TYPE tokenType = {};
        DWORD tokenLen = 0;
        if (!GetTokenInformation(token, TokenType, &tokenType, sizeof(tokenType), &tokenLen))
            abort();

        wprintf(L"  TokenType: %s\n", (tokenType == TokenPrimary) ? L"Primary" : L"Impersonation");
    }

    PrivilegeState privIncreaseQuta = {};
    PrivilegeState privAssignPrimaryToken = {};
    PrivilegeState privImpersonate = {};
    {
        LUID INCREASE_QUOTA{};
        BOOL ok = LookupPrivilegeValueW(nullptr, SE_INCREASE_QUOTA_NAME, &INCREASE_QUOTA);
        assert(ok);
        LUID ASSIGNPRIMARYTOKEN = {};
        ok = LookupPrivilegeValueW(nullptr, SE_ASSIGNPRIMARYTOKEN_NAME, &ASSIGNPRIMARYTOKEN);
        assert(ok);
        LUID IMPERSONATE = {};
        ok = LookupPrivilegeValueW(nullptr, SE_IMPERSONATE_NAME, &IMPERSONATE);
        assert(ok);

        std::vector<BYTE> privilegesBuffer(1024, (BYTE)0);
        {
            DWORD privilegesLength = 0;
            ok = GetTokenInformation(token, TokenPrivileges, privilegesBuffer.data(), (DWORD)privilegesBuffer.size(), &privilegesLength);
            assert(ok);
            privilegesBuffer.resize(privilegesLength);
        }
        auto* privileges = (TOKEN_PRIVILEGES*)privilegesBuffer.data();

        wprintf(L"  Privilege count: %u.\n", privileges->PrivilegeCount);
        for (size_t i = 0; i < privileges->PrivilegeCount; i++) {
            CheckPrivilegeEnabled(privileges->Privileges[i], INCREASE_QUOTA, privIncreaseQuta);
            CheckPrivilegeEnabled(privileges->Privileges[i], ASSIGNPRIMARYTOKEN, privAssignPrimaryToken);
            CheckPrivilegeEnabled(privileges->Privileges[i], IMPERSONATE, privImpersonate);
        }

        wprintf(L"  SE_INCREASE_QUOTA privilege %s\n", ToString(privIncreaseQuta));
        wprintf(L"  SE_ASSIGNPRIMARYTOKEN privilege %s\n", ToString(privAssignPrimaryToken));
        wprintf(L"  SE_IMPERSONATE privilege %s\n", ToString(privImpersonate));

        if (enableDisabled) {
            auto enablePrivilege = [token](LUID privVal) {
                // https://learn.microsoft.com/nb-no/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
                TOKEN_PRIVILEGES tp{};
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                tp.Privileges[0].Luid = privVal;

                if (!AdjustTokenPrivileges(token, /*disableAll*/false, &tp, 0, nullptr, nullptr)) {
                    DWORD err = GetLastError();
                    wprintf(L"ERROR: AdjustTokenPrivileges failed (%s)\n", ToString(err).c_str());
                    abort();
                }
            };

            if (privIncreaseQuta == PrivilegeState::Disabled) {
                wprintf(L"  Enabling SE_INCREASE_QUOTA...\n");
                enablePrivilege(INCREASE_QUOTA);
            }
            if (privAssignPrimaryToken == PrivilegeState::Disabled) {
                wprintf(L"  Enabling SE_ASSIGNPRIMARYTOKEN...\n");
                enablePrivilege(ASSIGNPRIMARYTOKEN);
            }
            if (privImpersonate == PrivilegeState::Disabled) {
                wprintf(L"  Enabling SE_IMPERSONATE...\n");
                enablePrivilege(IMPERSONATE);
            }
        }
    }

    return true;
}

/** Add a DACL entry to the window station or desktop security descriptor.
    Use BuildExplicitAccessWithNameW to initialize the "ea" argument. */
bool AddWindowDaclRight(HANDLE ws, EXPLICIT_ACCESS_W& ea) {
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
    return true;
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
