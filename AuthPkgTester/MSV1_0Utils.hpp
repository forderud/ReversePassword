#pragma once
#include <Windows.h>
#include <string>
#include <vector>


inline std::wstring ToWstring(const LSA_UNICODE_STRING& lsa_str) {
    if (lsa_str.Length == 0)
        return L"<empty>";
    return std::wstring(lsa_str.Buffer, lsa_str.Length / 2);
}

/** Prepare MSV1_0_INTERACTIVE_LOGON struct to be passed to LsaLogonUser when using authPkg=MSV1_0_PACKAGE_NAME. */
std::vector<BYTE> PrepareLogon_MSV1_0(std::wstring& domain, std::wstring& username, std::wstring& password) {
    // field sizes [bytes]
    auto domainSize = (USHORT)(2 * domain.size());
    auto usernameSize = (USHORT)(2 * username.size());
    auto passwordSize = (USHORT)(2 * password.size());

    // populate packed MSV1_0_INTERACTIVE_LOGON struct with domain, username & password at the end
    std::vector<BYTE> authInfo(sizeof(MSV1_0_INTERACTIVE_LOGON) + domainSize + usernameSize + passwordSize, (BYTE)0);
    auto* logon = (MSV1_0_INTERACTIVE_LOGON*)authInfo.data();
    logon->MessageType = MsV1_0InteractiveLogon;

    logon->LogonDomainName = {
        .Length = domainSize,
        .MaximumLength = domainSize,
        .Buffer = (wchar_t*)sizeof(MSV1_0_INTERACTIVE_LOGON), // relative address
    };

    logon->UserName = {
        .Length = usernameSize,
        .MaximumLength = usernameSize,
        .Buffer = (wchar_t*)(sizeof(MSV1_0_INTERACTIVE_LOGON) + domainSize), // relative address
    };

    logon->Password = {
        .Length = passwordSize,
        .MaximumLength = passwordSize,
        .Buffer = (wchar_t*)(sizeof(MSV1_0_INTERACTIVE_LOGON) + domainSize + usernameSize), // relative address
    };

    BYTE* domainStart = authInfo.data() + (size_t)logon->LogonDomainName.Buffer;
    memcpy(domainStart, domain.data(), domainSize);

    BYTE* usernameStart = authInfo.data() + (size_t)logon->UserName.Buffer;
    memcpy(usernameStart, username.data(), usernameSize);

    BYTE* passwordStart = authInfo.data() + (size_t)logon->Password.Buffer;
    memcpy(passwordStart, password.data(), passwordSize);

    return authInfo;
}

/** Print MSV1_0_INTERACTIVE_PROFILE fields to console. */
void Print(const MSV1_0_INTERACTIVE_PROFILE& p) {
    wprintf(L"MessageType: %u (MsV1_0InteractiveProfile=2)\n", p.MessageType);
    wprintf(L"LogonCount: %u\n", p.LogonCount);
    wprintf(L"BadPasswordCount: %u\n", p.BadPasswordCount);
    wprintf(L"LogonTime: 0x%llx\n", p.LogonTime.QuadPart);
    wprintf(L"LogoffTime: 0x%llx\n", p.LogoffTime.QuadPart);
    wprintf(L"KickOffTime: 0x%llx\n", p.KickOffTime.QuadPart);
    wprintf(L"PasswordLastSet: 0x%llx\n", p.PasswordLastSet.QuadPart);
    wprintf(L"PasswordCanChange: 0x%llx\n", p.PasswordCanChange.QuadPart);
    wprintf(L"PasswordMustChange: 0x%llx\n", p.PasswordMustChange.QuadPart);
    wprintf(L"LogonScript: %s\n", ToWstring(p.LogonScript).c_str());
    wprintf(L"HomeDirectory: %s\n", ToWstring(p.HomeDirectory).c_str());
    wprintf(L"FullName: %s\n", ToWstring(p.FullName).c_str());
    wprintf(L"ProfilePath: %s\n", ToWstring(p.ProfilePath).c_str());
    wprintf(L"HomeDirectoryDrive: %s\n", ToWstring(p.HomeDirectoryDrive).c_str());
    wprintf(L"LogonServer: %s\n", ToWstring(p.LogonServer).c_str());
    wprintf(L"UserFlags: %u\n", p.UserFlags);
}
