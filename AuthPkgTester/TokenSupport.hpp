#pragma once
#include <Windows.h>
#include <stdio.h>

enum class PrivilegeState {
    Missing,
    Enabled,
    Disabled,
};

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
        DWORD privilegesLength = 0;
        ok = GetTokenInformation(token, TokenPrivileges, privilegesBuffer.data(), (DWORD)privilegesBuffer.size(), &privilegesLength);
        assert(ok);
        privilegesBuffer.resize(privilegesLength);
        auto* privileges = (TOKEN_PRIVILEGES*)privilegesBuffer.data();

        wprintf(L"  Contain %u token privileges.\n", privileges->PrivilegeCount);
        for (size_t i = 0; i < privileges->PrivilegeCount; i++) {
            CheckPrivilegeEnabled(privileges->Privileges[i], INCREASE_QUOTA, privIncreaseQuta);
            CheckPrivilegeEnabled(privileges->Privileges[i], ASSIGNPRIMARYTOKEN, privAssignPrimaryToken);
            CheckPrivilegeEnabled(privileges->Privileges[i], IMPERSONATE_NAME, privImpersonateName);
        }

#if 0
        if (!hasIncreaseQuta)
            wprintf(L"  WARNING: SE_INCREASE_QUOTA_NAME privilege missing\n");
        if (!hasAssignPrimaryToken)
            wprintf(L"  WARNING: SE_ASSIGNPRIMARYTOKEN_NAME privilege missing\n");
#endif
        if (privImpersonateName != PrivilegeState::Enabled)
            wprintf(L"  WARNING: SE_IMPERSONATE_NAME privilege missing\n");
    }

    return true;
}