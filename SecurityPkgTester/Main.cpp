#define SECURITY_WIN32 // required by sspi.h
#include <windows.h>
#include <sspi.h>
#include <security.h> // for NEGOSSP_NAME_A, MICROSOFT_KERBEROS_NAME_A
#include <NTSecAPI.h> // for MSV1_0_PACKAGE_NAME
#include <SubAuth.h>
#include <cassert>
#include <iostream>
#include <tuple>
#include <vector>
#include "PrintInfo.hpp"

#pragma comment(lib, "Secur32.lib")


class LsaHandle {
public:
    LsaHandle() {
        // establish LSA connection
        NTSTATUS status = LsaConnectUntrusted(&m_lsa);
        assert(status == STATUS_SUCCESS);
    }
    ~LsaHandle() {
        // close LSA handle
        NTSTATUS status = LsaDeregisterLogonProcess(m_lsa);
        assert(status == STATUS_SUCCESS);
    }

    operator HANDLE() {
        return m_lsa;
    }
private:
    HANDLE m_lsa = 0;
};

ULONG GetAuthPackage(LsaHandle& lsa, const char* name) {
    LSA_STRING lsa_name {
        .Length = (USHORT)strlen(name),
        .MaximumLength = (USHORT)strlen(name),
        .Buffer = (char*)name,
    };

    ULONG authPkg = 0;
    NTSTATUS status = LsaLookupAuthenticationPackage(lsa, &lsa_name, &authPkg);
    if (status != STATUS_SUCCESS) {
        wprintf(L"ERROR: LsaLookupAuthenticationPackage failed with err: %u", status);
        abort();
    }

    return authPkg;
}

/** Prepare MSV1_0_INTERACTIVE_LOGON struct to be passed to LsaLogonUser when using authPkg=MSV1_0_PACKAGE_NAME. */
std::tuple<const char*, std::vector<BYTE>> PrepareLogon_MSV1_0(std::wstring& username, std::wstring& password) {
    std::wstring domain = L"";

    // field sizes [bytes]
    auto domainSize = (USHORT)(2 * domain.size());
    auto usernameSize = (USHORT)(2 * username.size());
    auto passwordSize = (USHORT)(2 * password.size());

    // populate packed MSV1_0_INTERACTIVE_LOGON struct with domain, username & password at the end
    std::vector<BYTE> authInfo; // MSV1_0_INTERACTIVE_LOGON
    authInfo.resize(sizeof(MSV1_0_INTERACTIVE_LOGON) + domainSize + usernameSize + passwordSize);
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

    return { MSV1_0_PACKAGE_NAME, authInfo };
}

NTSTATUS LsaLogonUserInteractive(LsaHandle& lsa, const char* authPkgName, const std::vector<BYTE>& authInfo) {
    const char ORIGIN[] = "SecurityPkgTester";
    LSA_STRING origin {
        .Length = (USHORT)strlen(ORIGIN),
        .MaximumLength = (USHORT)strlen(ORIGIN),
        .Buffer = (char*)ORIGIN,
    };

    TOKEN_SOURCE sourceContext{};
    {
        // Populate SourceName & SourceIdentifier fields
        HANDLE userToken = GetCurrentProcessToken();
        DWORD returnLength = 0;
        GetTokenInformation(userToken, TokenSource, &sourceContext, sizeof(sourceContext), &returnLength);
        assert(returnLength == sizeof(sourceContext));
    }

    ULONG authPkg = GetAuthPackage(lsa, authPkgName);
    
    // output arguments
    void* profileBuffer = nullptr;
    ULONG profileBufferLen = 0;
    LUID logonId{};
    HANDLE token = 0;
    QUOTA_LIMITS quotas{};
    NTSTATUS subStatus = 0;

    NTSTATUS ret = LsaLogonUser(lsa, &origin, SECURITY_LOGON_TYPE::Interactive, authPkg, (void*)authInfo.data(), (ULONG)authInfo.size(), /*LocalGroups*/nullptr, &sourceContext, &profileBuffer, &profileBufferLen, &logonId, &token, &quotas, &subStatus);

    LsaFreeReturnBuffer(profileBuffer);

    return ret;
}


int wmain(int argc, wchar_t* argv[]) {
    LsaHandle lsa;

    if (argc == 1) {
        // query installed security packages
        {
            // NOTE: EnumerateSecurityPackages doesn't seem to detect MSV1_0
            ULONG package_count = 0;
            SecPkgInfoA* packages = nullptr;
            SECURITY_STATUS ret = EnumerateSecurityPackagesA(&package_count, &packages);
            if (ret != SEC_E_OK) {
                wprintf(L"ERROR: EnumerateSecurityPackagesW failed with error %u\n", ret);
                return -1;
            }

            wprintf(L"Installed security packages:\n");
            for (ULONG idx = 0; idx < package_count; idx++) {
                SecPkgInfoA& pkg = packages[idx];
                wprintf(L"\n");
                PrintSecPkgInfo(pkg);

                ULONG authPkg = GetAuthPackage(lsa, pkg.Name);
                wprintf(L"  AuthPkgID: %u\n", authPkg);
            }

            FreeContextBuffer(packages);
        }

        wprintf(L"\n");
        wprintf(L"Predefined security packages:\n");
        const char* predefined_packages[] = { NEGOSSP_NAME_A, MICROSOFT_KERBEROS_NAME_A, MSV1_0_PACKAGE_NAME };
        for (const char* package : predefined_packages) {
            ULONG authPkg = GetAuthPackage(lsa, package);
            wprintf(L"* Package: %hs\n", package);
            wprintf(L"  AuthPkgID: %u\n", authPkg);
        }
    } else if (argc == 3) {
        // try to login with username & password against MSV1_0
        std::wstring username = argv[1];
        std::wstring password = argv[2];

        wprintf(L"\n");
        wprintf(L"Attempting local interactive logon against the MSV1_0 authentication package...\n");
        auto [authPkgName, authInfo] = PrepareLogon_MSV1_0(username, password);
        NTSTATUS ret = LsaLogonUserInteractive(lsa, authPkgName, authInfo);
        if (ret != STATUS_SUCCESS) {
            if (ret == STATUS_LOGON_FAILURE) // observed both for unknonw user and invalid password
                wprintf(L"ERROR: LsaLogonUser STATUS_LOGON_FAILURE\n");
            else
                wprintf(L"ERROR: LsaLogonUser failed, ret: 0x%x\n", ret);
        } else {
            wprintf(L"SUCCESS: User logon succeeded.\n");
        }
    } else {
        wprintf(L"USAGE:\n");
        wprintf(L"  List security packages: SecurityPkgTester.exe\n");
        wprintf(L"  Attempt MSV1_0 login: SecurityPkgTester.exe <username> <password>\n");
    }
}
