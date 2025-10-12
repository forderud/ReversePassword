#pragma once
#include <Windows.h>
#include <string>
#include <vector>


/** Prepare MSV1_0_INTERACTIVE_LOGON struct to be passed to LsaLogonUser when using authPkg=MSV1_0_PACKAGE_NAME. */
std::vector<BYTE> PrepareLogon_MSV1_0(std::wstring& username, std::wstring& password) {
    std::wstring domain = L"";

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
