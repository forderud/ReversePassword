#pragma once
#include <Windows.h>
#include <stdio.h>


bool IsEqual(LUID left, LUID right) {
    return (left.LowPart == right.LowPart) && (left.HighPart == right.HighPart);
}

bool VerifyThatTokenIsPrimary(HANDLE token) {
    {
        // verify that "token" type is TokenPrimary
        TOKEN_TYPE tokenType = {};
        DWORD tokenLen = 0;
        if (!GetTokenInformation(token, TokenType, &tokenType, sizeof(tokenType), &tokenLen))
            abort();
        if (tokenType != TokenPrimary) {
            wprintf(L"ERROR: Incorrect process token type. Need primary token.\n");
            return false;
        }
    }

    return true;
}


bool CheckTokenPrivileges(HANDLE token) {
    {
        TOKEN_TYPE tokenType = {};
        DWORD tokenLen = 0;
        if (!GetTokenInformation(token, TokenType, &tokenType, sizeof(tokenType), &tokenLen))
            abort();

        wprintf(L"  TokenType: %s\n", (tokenType == TokenPrimary) ? L"Primary" : L"Impersonation");
    }

    bool hasIncreaseQuta = false;
    bool hasAssignPrimaryToken = false;
    bool hasImpersonateName = false;
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
            if (IsEqual(privileges->Privileges[i].Luid, INCREASE_QUOTA))
                hasIncreaseQuta = true;
            if (IsEqual(privileges->Privileges[i].Luid, ASSIGNPRIMARYTOKEN))
                hasAssignPrimaryToken = true;
            if (IsEqual(privileges->Privileges[i].Luid, IMPERSONATE_NAME))
                hasImpersonateName = true;
        }

#if 0
        if (!hasIncreaseQuta)
            wprintf(L"  WARNING: SE_INCREASE_QUOTA_NAME privilege missing\n");
        if (!hasAssignPrimaryToken)
            wprintf(L"  WARNING: SE_ASSIGNPRIMARYTOKEN_NAME privilege missing\n");
#endif
        if (!hasImpersonateName)
            wprintf(L"  WARNING: SE_IMPERSONATE_NAME privilege missing\n");
    }

    return true;
}