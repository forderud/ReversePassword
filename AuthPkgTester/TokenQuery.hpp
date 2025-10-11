#pragma once
#include <Windows.h>
#include <aclapi.h>
#include <stdio.h>


const std::wstring ToString(DWORD err) {
    switch (err) {
    case ERROR_INVALID_HANDLE: return L"ERROR_INVALID_HANDLE";
    case ERROR_PRIVILEGE_NOT_HELD: return L"ERROR_PRIVILEGE_NOT_HELD";
    case ERROR_INVALID_PARAMETER: return L"ERROR_INVALID_PARAMETER";
    case ERROR_TOKEN_ALREADY_IN_USE: return L"ERROR_TOKEN_ALREADY_IN_USE";
    case ERROR_INVALID_SECURITY_DESCR: return L"ERROR_INVALID_SECURITY_DESCR";
    }

    return L"error " + std::to_wstring(err);
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

void CheckPrivilegeEnabled(LUID_AND_ATTRIBUTES entry, LUID priv, /*out*/PrivilegeState& state) {
    bool match = (entry.Luid.LowPart == priv.LowPart) && (entry.Luid.HighPart == priv.HighPart);
    if (!match)
        return;

    if (entry.Attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT))
        state = PrivilegeState::Enabled;
    else
        state = PrivilegeState::Disabled;
}


bool CheckTokenPrivileges(HANDLE token) {
    {
        TOKEN_TYPE tokenType = {};
        DWORD tokenLen = 0;
        if (!GetTokenInformation(token, TokenType, &tokenType, sizeof(tokenType), &tokenLen))
            abort();

        wprintf(L"  TokenType: %s\n", (tokenType == TokenPrimary) ? L"Primary" : L"Impersonation");
    }

    PrivilegeState privIncreaseQuta = {};
    PrivilegeState privAssignPrimaryToken = {};
    PrivilegeState privImpersonateName = {};
    {
        LUID INCREASE_QUOTA{};
        BOOL ok = LookupPrivilegeValueW(nullptr, SE_INCREASE_QUOTA_NAME, &INCREASE_QUOTA);
        assert(ok);
        LUID ASSIGNPRIMARYTOKEN = {};
        ok = LookupPrivilegeValueW(nullptr, SE_ASSIGNPRIMARYTOKEN_NAME, &ASSIGNPRIMARYTOKEN);
        assert(ok);
        LUID IMPERSONATE_NAME = {};
        ok = LookupPrivilegeValueW(nullptr, SE_IMPERSONATE_NAME, &IMPERSONATE_NAME);
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
            CheckPrivilegeEnabled(privileges->Privileges[i], IMPERSONATE_NAME, privImpersonateName);
        }

#if 0
        wprintf(L"  SE_INCREASE_QUOTA_NAME privilege %s\n", ToString(privIncreaseQuta));
        wprintf(L"  SE_ASSIGNPRIMARYTOKEN_NAME privilege %s\n", ToString(privAssignPrimaryToken));
#endif
        wprintf(L"  SE_IMPERSONATE_NAME privilege %s\n", ToString(privImpersonateName));

#if 0
        if (privImpersonateName != PrivilegeState::Enabled) {
            assert(privImpersonateName == PrivilegeState::Missing);

            // append SE_IMPERSONATE_NAME=enabled privilege at the end of the buffer
            privilegesBuffer.resize(privilegesBuffer.size() + sizeof(LUID_AND_ATTRIBUTES), (BYTE)0);
            privileges = (TOKEN_PRIVILEGES*)privilegesBuffer.data();

            privileges->PrivilegeCount += 1;
            privileges->Privileges[privileges->PrivilegeCount - 1].Luid = IMPERSONATE_NAME;
            privileges->Privileges[privileges->PrivilegeCount - 1].Attributes = SE_PRIVILEGE_ENABLED;

            wprintf(L"  Attempting to enable SE_IMPERSONATE_NAME (doesn't work)...\n");
            if (!AdjustTokenPrivileges(token, false, privileges, 0, nullptr, nullptr)) {
                DWORD err = GetLastError();
                wprintf(L"ERROR: AdjustTokenPrivileges failed (%s)\n", ToString(err).c_str());
            }
        }
#endif
    }

    return true;
}


bool CheckTokenAccessRights(HANDLE token) {
    // TODO: Check TOKEN_QUERY, TOKEN_DUPLICATE, and TOKEN_ASSIGN_PRIMARY access rights that's required by CreateProcessWithTokenW

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

        wprintf(L"  DACL revision: %u\n", relSd->Revision);
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
#if 0
        DWORD desiredAccess = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;

        BOOL daclPresent = false;
        ACL* dacl = nullptr;
        BOOL daclDefaulted = false;
        BOOL ok = GetSecurityDescriptorDacl(relSd, &daclPresent, &dacl, &daclDefaulted);
        assert(ok);

        wchar_t name[1024] = {};
        DWORD nameLen = 1024;
        if (!GetUserNameW(name, &nameLen))
            abort();

        EXPLICIT_ACCESS_W ea{};
        BuildExplicitAccessWithNameW(&ea, name, desiredAccess, GRANT_ACCESS, 0);
        ea.Trustee.TrusteeType = TRUSTEE_IS_USER;

        ACL* newDacl = nullptr;
        DWORD ret = SetEntriesInAclW(1, &ea, /*oldAcl*/dacl, &newDacl);
        assert(ret == ERROR_SUCCESS);

#if 1
        std::vector<BYTE> newSdBuf(SECURITY_DESCRIPTOR_MIN_LENGTH, (BYTE)0);
        auto* newSd = (SECURITY_DESCRIPTOR*)newSdBuf.data();
        ok = InitializeSecurityDescriptor(newSd, SECURITY_DESCRIPTOR_REVISION);
        assert(ok);
#endif

        // replace DACL (SD must be in absolute format)
        ok = SetSecurityDescriptorDacl(relSd, daclPresent, newDacl, daclDefaulted);
        if (!ok) {
            DWORD err = GetLastError();
            wprintf(L"ERROR: SetEntriesInAclW failed (%s)\n", ToString(err).c_str());
            abort();
        }
        //LocalFree(newDacl);

        // update security settings
        ok = SetKernelObjectSecurity(token, DACL_SECURITY_INFORMATION, relSd);
        assert(ok);
#endif
    }

    return true;
}
