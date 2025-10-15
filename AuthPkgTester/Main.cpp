#define UMDF_USING_NTSTATUS 
#define SECURITY_WIN32 // required by sspi.h
#include <windows.h>
#include <sspi.h>
#include <security.h> // for NEGOSSP_NAME_A, MICROSOFT_KERBEROS_NAME_A
#include <NTSecAPI.h> // for MSV1_0_PACKAGE_NAME
#include <ntstatus.h>
#include <SubAuth.h>
#include <userenv.h> // for CreateEnvironmentBlock
#include <sddl.h>
#include <cassert>
#include <iostream>
#include <tuple>
#include "PrintInfo.hpp"
#include "TokenUtils.hpp"
#include "MSV1_0Utils.hpp"

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Userenv.lib")

#define START_SEPARATE_WINDOW
#define USE_LSA_LOGONUSER
#define USE_CREATE_PROCESS_WITH_TOKEN


/** Converts unicode string to ASCII */
inline std::string ToAscii(const std::wstring& w_str) {
    std::string s_str(w_str.size(), '\0');
    size_t charsConverted = 0;
    auto err = wcstombs_s(&charsConverted, s_str.data(), s_str.size() + 1, w_str.c_str(), s_str.size());
    assert(!err); (void)err; // mute unreferenced variable warning
    return s_str;
}

class LsaHandle {
public:
    LsaHandle() {
        // establish LSA connection
        NTSTATUS status = LsaConnectUntrusted(&m_lsa);
        assert(status == STATUS_SUCCESS);

#if 0
        const char name[] = "AuthPkgTester";
        LSA_STRING lsa_name{
            .Length = sizeof(name) - 1,
            .MaximumLength = sizeof(name) - 1,
            .Buffer = (char*)name,
        };

        LSA_OPERATIONAL_MODE mode = 0;
        status = LsaRegisterLogonProcess(&lsa_name, /*out*/&m_lsa, /*out*/&mode); // require SeTcbPrivilege
        assert(status == STATUS_PORT_CONNECTION_REFUSED);
        abort();
#endif
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

NTSTATUS GetAuthPackage(LsaHandle& lsa, const wchar_t* name, /*out*/ULONG* authPkg) {
    std::string name_a = ToAscii(name);

    LSA_STRING lsa_name{
        .Length = (USHORT)name_a.size(),
        .MaximumLength = (USHORT)name_a.size(),
        .Buffer = name_a.data(),
    };

    NTSTATUS status = LsaLookupAuthenticationPackage(lsa, &lsa_name, authPkg);
    if (status != STATUS_SUCCESS) {
        if (status == STATUS_NO_SUCH_PACKAGE)
            wprintf(L"ERROR: LsaLookupAuthenticationPackage failed with STATUS_NO_SUCH_PACKAGE\n");
        else
            wprintf(L"ERROR: LsaLookupAuthenticationPackage failed with err: 0x%x\n", status);
        return status;
    }

    return status;
}

/** Aleternative to GetCurrentProcessToken() with more privileges. */
HANDLE GetCurrentProcessTokenEx() {
    HANDLE procToken = 0;
    if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &procToken))
        abort();

    // copy token to avoid ERROR_TOKEN_ALREADY_IN_USE
    HANDLE token = 0;
    if (!DuplicateTokenEx(procToken, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &token))
        abort();
    return token;
}

NTSTATUS CreateCmdProcessWithTokenW(HANDLE token, const std::wstring& username, PSID logonSid) {
    wprintf(L"Inspecting current process privileges:\n");
    AdjustTokenPrivileges(GetCurrentProcessTokenEx());

    wprintf(L"Inspecting user token privileges:\n");
    AdjustTokenPrivileges(token);

    wprintf(L"\n");
    wprintf(L"Attempting to start cmd.exe through the logged-in user...\n");

#if 0
    // not sure if this is needed when using LOGON_WITH_PROFILE
    PROFILEINFOW profile = {
        .dwSize = sizeof(profile),
        .lpUserName = (wchar_t*)username.c_str(),
    };
    if (!LoadUserProfileW(token, &profile))
        abort();
#endif

    GrantWindowStationDesktopAccess(logonSid);

    STARTUPINFOW si = {
        .cb = sizeof(si),
        //.lpDesktop = (wchar_t*)L"winsta0\\default",
#ifndef START_SEPARATE_WINDOW
        .hStdInput = GetStdHandle(STD_INPUT_HANDLE),
        .hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE),
        .hStdError = GetStdHandle(STD_ERROR_HANDLE),
#endif
    };
    PROCESS_INFORMATION pi = {};

    std::wstring cmdLine = L"C:\\Windows\\System32\\cmd.exe";
    const wchar_t* appName = cmdLine.c_str();
    DWORD creationFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_NEW_PROCESS_GROUP;
#ifdef START_SEPARATE_WINDOW
    creationFlags |= CREATE_NEW_CONSOLE;
#else
    creationFlags |= CREATE_NO_WINDOW;
#endif
    const wchar_t* curDir = L"C:\\";
#ifdef USE_CREATE_PROCESS_WITH_TOKEN
    // WARNING: CreateProcessWithTokenW succeeds, but cmd.exe crashes immediately with 0xc0000142 (DLL initialization failed) if using token from LsaLogonUser
    // CreateProcessWithTokenW require TOKEN_QUERY, TOKEN_DUPLICATE & TOKEN_ASSIGN_PRIMARY access rights 
    DWORD logonFlags = LOGON_WITH_PROFILE;
    BOOL ok = CreateProcessWithTokenW(token, logonFlags, appName, cmdLine.data(), creationFlags, /*env*/nullptr, curDir, &si, &pi);
#else
    // WARNING: CreateProcessAsUserW fails, unless running through the SYSTEM account. Even then, cmd.exe crashes immediately with 0xc0000142 (DLL initialization failed) if using token from LsaLogonUser

    void* userEnvironment = nullptr;
    if (!CreateEnvironmentBlock(&userEnvironment, token, /*inherit*/false))
        abort();
    creationFlags |= CREATE_UNICODE_ENVIRONMENT; // environment loading required for CreateProcessAsUserW

    // CreateProcessAsUserW require SE_INCREASE_QUOTA_NAME and may require SE_ASSIGNPRIMARYTOKEN_NAME that admin accounts usually lack
    BOOL ok = CreateProcessAsUserW(token, appName, cmdLine.data(), /*proc.sec*/nullptr, /*thread sec*/nullptr, /*inherit*/false, creationFlags, /*env*/userEnvironment, curDir, &si, &pi);

    // cannot use CreateProcessW with ImpersonateLoggedOnUser, since it doesn't support impersonation

    DestroyEnvironmentBlock(userEnvironment);
#endif
    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"ERROR: Unable to start cmd.exe through the logged in user (%s).\n", ToString(err).c_str());
        return err;
    }

    wprintf(L"Waiting for process to terminate...\n");
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return STATUS_SUCCESS;
}

NTSTATUS LsaLogonUserInteractive(LsaHandle& lsa, const wchar_t* authPkgName, const std::vector<BYTE>& authInfo, const std::wstring& username, const std::wstring& password) {
    //wprintf(L"INFO: AuthenticationInformationLength: %u\n", (uint32_t)authInfo.size());

    // output arguments
    void* profileBuffer = nullptr;
    ULONG profileBufferLen = 0;
    HANDLE token = 0;
    QUOTA_LIMITS quotas{};
    PSID logonSid = nullptr; // logon session SID in "S-1-5-5-X-Y" format

#ifndef USE_LSA_LOGONUSER
    {
#if 0
        wchar_t domain[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD domainLen = MAX_COMPUTERNAME_LENGTH;
        GetComputerNameW(domain, &domainLen);
        DWORD logonProvider = LOGON32_PROVIDER_WINNT50; // use negotiate logon provider (require passing domain=computername)
#else
        wchar_t* domain = nullptr;
        DWORD logonProvider = LOGON32_PROVIDER_DEFAULT; // default logon (seem to work better for local accounts)
#endif
        BOOL ok = LogonUserExW(username.c_str(), domain, password.c_str(), SECURITY_LOGON_TYPE::Interactive, logonProvider, &token, &logonSid, &profileBuffer, &profileBufferLen, &quotas);
        if (!ok) {
            DWORD err = GetLastError();
            wprintf(L"LogonUserExW failed (%s)\n", ToString(err).c_str());
            abort();
        }
        wprintf(L"SUCCESS: LogonUserExW succeeded.\n");
    }
#else
    {
        const char ORIGIN[] = "AuthPkgTester"; // "Advapi32 Logon";
        LSA_STRING origin{
            .Length = (USHORT)strlen(ORIGIN),
            .MaximumLength = (USHORT)strlen(ORIGIN),
            .Buffer = (char*)ORIGIN,
        };

        ULONG authPkg = 0;
        NTSTATUS status = GetAuthPackage(lsa, authPkgName, &authPkg);
        if (status != STATUS_SUCCESS)
            return status;

        TOKEN_SOURCE sourceContext{
            .SourceName = "APtest",
            .SourceIdentifier{},
        };
        AllocateLocallyUniqueId(&sourceContext.SourceIdentifier);
        wprintf(L"SourceContext ID: High=%u, Low=%u\n", sourceContext.SourceIdentifier.HighPart, sourceContext.SourceIdentifier.LowPart);

        NTSTATUS subStatus = 0;
        LUID logonId{};
        // "LocalGroups" argument not set because it require SeTcbPrivilege
        NTSTATUS ret = LsaLogonUser(lsa, &origin, SECURITY_LOGON_TYPE::Interactive, authPkg, (void*)authInfo.data(), (ULONG)authInfo.size(), /*LocalGroups*/nullptr, &sourceContext, &profileBuffer, &profileBufferLen, &logonId, &token, &quotas, &subStatus);
        if (ret != STATUS_SUCCESS) {
            wprintf(L"LsaLogonUser failed (%s)\n", ToString(ret).c_str());
            abort();
        }
        wprintf(L"SUCCESS: LsaLogonUser succeeded.\n");

        // create logon session SID in "S-1-5-5-X-Y" format
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        BOOL ok = AllocateAndInitializeSid(&ntAuthority, 3, 5, logonId.HighPart, logonId.LowPart, 0, 0, 0, 0, 0, &logonSid);
        assert(ok);
    }
#endif

    {
        wchar_t* sidStr = nullptr;
        ConvertSidToStringSidW(logonSid, &sidStr);
        wprintf(L"Logon session SID: %s\n", sidStr);
        LocalFree(sidStr);
    }

    wprintf(L"profileBufferLen: %u\n", profileBufferLen);
    if (profileBufferLen >= sizeof(MSV1_0_INTERACTIVE_PROFILE)) {
        static_assert(sizeof(MSV1_0_INTERACTIVE_PROFILE) == 160);
        auto* profile = (MSV1_0_INTERACTIVE_PROFILE*)profileBuffer;
        // print fields to console
        Print(*profile);
    }

    NTSTATUS ret = CreateCmdProcessWithTokenW(token, username, logonSid);

    LsaFreeReturnBuffer(profileBuffer);
    CloseHandle(token);
    FreeSid(logonSid);
    return ret;
}


int wmain(int argc, wchar_t* argv[]) {
    {
#if 0
        SECURITY_PACKAGE_OPTIONS options{
            .Size = sizeof(options),
            .Type = SECPKG_OPTIONS_TYPE_LSA,
            .Flags = 0, // reserved
            .SignatureSize = 0,
            .Signature = 0,
        };
        SECURITY_STATUS ret = AddSecurityPackageW((wchar_t*)L"C:\\Windows\\System32\\NoPasswordAuthPkg.dll", &options);
        if (ret == SEC_E_OK)
            wprintf(L"INFO: NoPasswordAuthPkg.dll loaded\n");
        else
            wprintf(L"WARNING: Unable to load NoPasswordAuthPkg.dll (error %u)\n", ret);
#endif
    }

    LsaHandle lsa;

    if (argc == 1) {
        // query installed security packages
        {
            // NOTE: EnumerateSecurityPackages doesn't seem to detect MSV1_0
            ULONG package_count = 0;
            SecPkgInfoW* packages = nullptr;
            SECURITY_STATUS ret = EnumerateSecurityPackagesW(&package_count, &packages);
            if (ret != SEC_E_OK) {
                wprintf(L"ERROR: EnumerateSecurityPackagesW failed with error %u\n", ret);
                return -1;
            }

            wprintf(L"Installed security packages:\n");
            for (ULONG idx = 0; idx < package_count; idx++) {
                auto& pkg = packages[idx];
                wprintf(L"\n");
                PrintSecPkgInfo(pkg);

                ULONG authPkg = 0;
                if (GetAuthPackage(lsa, pkg.Name, &authPkg) == STATUS_SUCCESS)
                    wprintf(L"  AuthPkgID: %u\n", authPkg);
            }

            FreeContextBuffer(packages);
        }

        wprintf(L"\n");
        wprintf(L"Predefined security packages:\n");
        const wchar_t* predefined_packages[] = { NEGOSSP_NAME_W, MICROSOFT_KERBEROS_NAME_W, MSV1_0_PACKAGE_NAMEW };
        for (auto* package : predefined_packages) {
            ULONG authPkg = 0;
            wprintf(L"* Package: %s\n", package);
            if (GetAuthPackage(lsa, package, &authPkg) == STATUS_SUCCESS)
                wprintf(L"  AuthPkgID: %u\n", authPkg);
        }
    } else if (argc >= 3) {
        size_t argIdx = 1;
        const wchar_t* authPkgName = MSV1_0_PACKAGE_NAMEW; // default to MSV1_0
        if (argc >= 4)
            authPkgName = argv[argIdx++];

        // try to login with username & password
        std::wstring username = argv[argIdx++];
        std::wstring password = argv[argIdx++];

        wprintf(L"\n");
        wprintf(L"Attempting local interactive logon against the %s authentication package...\n", authPkgName);
        std::vector<BYTE> authInfo;
        if (std::wstring(authPkgName) == MSV1_0_PACKAGE_NAMEW)
            authInfo = PrepareLogon_MSV1_0(username, password);
        else
            authInfo = PrepareLogon_MSV1_0(username, password); // TODO: Replace with suitable authInfo for the selected authPkg

        NTSTATUS ret = LsaLogonUserInteractive(lsa, authPkgName, authInfo, username, password);
        if (ret != STATUS_SUCCESS) {
            if (ret == STATUS_INVALID_PARAMETER)
                wprintf(L"ERROR: LsaLogonUser failed with STATUS_INVALID_PARAMETER\n");
            else if (ret == STATUS_LOGON_FAILURE) // observed both for unknonw user and invalid password
                wprintf(L"ERROR: LsaLogonUser failed with STATUS_LOGON_FAILURE\n");
            else if (ret == RPC_NT_CALL_FAILED)
                wprintf(L"ERROR: LsaLogonUser failed with RPC_NT_CALL_FAILED\n");
            else
                wprintf(L"ERROR: LsaLogonUser failed, ret: 0x%x\n", ret);
        } else {
            wprintf(L"SUCCESS: User logon succeeded.\n");
        }
    } else {
        wprintf(L"USAGE:\n");
        wprintf(L"  List security packages: AuthPkgTester.exe\n");
        wprintf(L"  Attempt MSV1_0 login: AuthPkgTester.exe [auth-package] <username> <password>\n");
    }
}
