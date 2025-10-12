#define UMDF_USING_NTSTATUS 
#define SECURITY_WIN32 // required by sspi.h
#include <windows.h>
#include <sspi.h>
#include <security.h> // for NEGOSSP_NAME_A, MICROSOFT_KERBEROS_NAME_A
#include <NTSecAPI.h> // for MSV1_0_PACKAGE_NAME
#include <ntstatus.h>
#include <SubAuth.h>
#include <userenv.h> // for CreateEnvironmentBlock
#include <cassert>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>
#include "PrintInfo.hpp"
#include "TokenUtils.hpp"

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Userenv.lib")


/** Converts unicode string to ASCII */
inline std::string ToAscii(const std::wstring& w_str) {
    std::string s_str(w_str.size(), '\0');
    size_t charsConverted = 0;
    auto err = wcstombs_s(&charsConverted, s_str.data(), s_str.size() + 1, w_str.c_str(), s_str.size());
    assert(!err); (void)err; // mute unreferenced variable warning
    return s_str;
}

inline std::wstring ToWstring(LSA_UNICODE_STRING& lsa_str) {
    if (lsa_str.Length == 0)
        return L"<empty>";
    return std::wstring(lsa_str.Buffer, lsa_str.Length / 2);
}

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

NTSTATUS CreateCmdProcessWithTokenW(HANDLE token, const std::wstring& username, const std::wstring& password) {
    wprintf(L"Inspecting current process privileges:\n");
    AdjustTokenPrivileges(GetCurrentProcessTokenEx());

#if 0
    // replace "token" with the primary token for the current user
    // useful for verifying the CreateProcessWithTokenW call below
    token = GetCurrentProcessTokenEx();
#endif

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

    {
        // https://learn.microsoft.com/en-us/windows/win32/winstation/window-station-security-and-access-rights
        HWINSTA ws = OpenWindowStationW(L"winsta0", /*inherit*/false, READ_CONTROL | WRITE_DAC);
        assert(ws);

        // Grant WINSTA_ALL_ACCESS to "username"
        EXPLICIT_ACCESS_W ea{};
        BuildExplicitAccessWithNameW(&ea, (wchar_t*)username.c_str(), WINSTA_ALL_ACCESS , GRANT_ACCESS, /*inherit*/false);
        ea.Trustee.TrusteeType = TRUSTEE_IS_USER;

        bool ok = AddWindowDaclRight(ws, ea);
        assert(ok);

        CloseWindowStation(ws);
    }
    {
        // https://learn.microsoft.com/en-us/windows/win32/winstation/desktop-security-and-access-rights
        HDESK desk = OpenInputDesktop(0, /*inherit*/false, READ_CONTROL | WRITE_DAC);
        assert(desk);

        // Grant WINSTA_ALL_ACCESS to "username"
        EXPLICIT_ACCESS_W ea{};
        BuildExplicitAccessWithNameW(&ea, (wchar_t*)username.c_str(), GENERIC_ALL, GRANT_ACCESS, /*inherit*/false);
        ea.Trustee.TrusteeType = TRUSTEE_IS_USER;

        bool ok = AddWindowDaclRight(desk, ea);
        assert(ok);

        CloseDesktop(desk);
    }

    STARTUPINFOW si = {
        .cb = sizeof(si),
        //.lpDesktop = (wchar_t*)L"winsta0\\default",
    };
    PROCESS_INFORMATION pi = {};

    DWORD logonFlags = LOGON_WITH_PROFILE;
    const wchar_t* appName = nullptr;
    std::wstring cmdLine = L"cmd.exe";
    DWORD creationFlags = CREATE_DEFAULT_ERROR_MODE | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP; // | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    const wchar_t* curDir = L"C:\\";
#if 1
    // actual call that we want to work
    // CreateProcessWithTokenW require TOKEN_QUERY, TOKEN_DUPLICATE & TOKEN_ASSIGN_PRIMARY access rights 
    BOOL ok = CreateProcessWithTokenW(token, logonFlags, appName, cmdLine.data(), creationFlags, /*env*/nullptr, curDir, &si, &pi);
#elif 0
    // alternative function that fail with ERROR_PRIVILEGE_NOT_HELD
    // CreateProcessAsUserW require SE_INCREASE_QUOTA_NAME and may require SE_ASSIGNPRIMARYTOKEN_NAME
    BOOL ok = CreateProcessAsUserW(token, appName, cmdLine.data(), /*proc.sec*/nullptr, /*thread sec*/nullptr, /*inherit*/false, creationFlags, /*env*/nullptr, curDir, &si, &pi);

    // cannot use CreateProcessW with ImpersonateLoggedOnUser, since it doesn't support impersonation
#else
    // compatibility testing call
    BOOL ok = CreateProcessWithLogonW(username.c_str(), /*domain*/nullptr, password.c_str(), logonFlags, appName, cmdLine.data(), creationFlags, /*env*/nullptr, curDir, &si, &pi);
#endif
    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"ERROR: Unable to start cmd.exe through the logged in user (%s).\n", ToString(err).c_str());
        return err;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return STATUS_SUCCESS;
}

NTSTATUS LsaLogonUserInteractive(LsaHandle& lsa, const wchar_t* authPkgName, const std::vector<BYTE>& authInfo, const std::wstring& username, const std::wstring& password) {
    //wprintf(L"INFO: AuthenticationInformationLength: %u\n", (uint32_t)authInfo.size());

    const char ORIGIN[] = "AuthPkgTester";
    LSA_STRING origin {
        .Length = (USHORT)strlen(ORIGIN),
        .MaximumLength = (USHORT)strlen(ORIGIN),
        .Buffer = (char*)ORIGIN,
    };

    TOKEN_SOURCE sourceContext{};
    {
        // Populate SourceName & SourceIdentifier fields
        HANDLE userToken = GetCurrentProcessTokenEx();
        DWORD returnLength = 0;
        GetTokenInformation(userToken, TokenSource, &sourceContext, sizeof(sourceContext), &returnLength);
        assert(returnLength == sizeof(sourceContext));
    }

    ULONG authPkg = 0;
    NTSTATUS status = GetAuthPackage(lsa, authPkgName, &authPkg);
    if (status != STATUS_SUCCESS)
        return status;
    
    // output arguments
    void* profileBuffer = nullptr;
    ULONG profileBufferLen = 0;
    LUID logonId{};
    HANDLE token = 0;
    QUOTA_LIMITS quotas{};

#if 0
    {
        DWORD logonProvider = LOGON32_PROVIDER_DEFAULT; // or LOGON32_PROVIDER_WINNT50 or LOGON32_PROVIDER_WINNT40
        PSID logonSid = nullptr;
        BOOL ok = LogonUserExW(username.c_str(), nullptr, password.c_str(), SECURITY_LOGON_TYPE::Interactive, logonProvider, &token, &logonSid, &profileBuffer, &profileBufferLen, &quotas);
        if (!ok) {
            DWORD err = GetLastError();
            wprintf(L"LogonUserExW failed (%s)\n", ToString(err).c_str());
            abort();
        }
        FreeSid(logonSid);
    }
#else
    {
        NTSTATUS subStatus = 0;
        NTSTATUS ret = LsaLogonUser(lsa, &origin, SECURITY_LOGON_TYPE::Interactive, authPkg, (void*)authInfo.data(), (ULONG)authInfo.size(), /*LocalGroups*/nullptr, &sourceContext, &profileBuffer, &profileBufferLen, &logonId, &token, &quotas, &subStatus);
        if (ret != STATUS_SUCCESS)
            return ret;
    }
#endif

    wprintf(L"profileBufferLen: %u\n", profileBufferLen);
    if (profileBufferLen >= sizeof(MSV1_0_INTERACTIVE_PROFILE)) {
        static_assert(sizeof(MSV1_0_INTERACTIVE_PROFILE) == 160);
        auto* profile = (MSV1_0_INTERACTIVE_PROFILE*)profileBuffer;

        // print MSV1_0_INTERACTIVE_PROFILE fields to console
        wprintf(L"MessageType: %u (MsV1_0InteractiveProfile=2)\n", profile->MessageType);
        wprintf(L"LogonCount: %u\n", profile->LogonCount);
        wprintf(L"BadPasswordCount: %u\n", profile->BadPasswordCount);
        wprintf(L"LogonTime: 0x%llx\n", profile->LogonTime.QuadPart);
        wprintf(L"LogoffTime: 0x%llx\n", profile->LogoffTime.QuadPart);
        wprintf(L"KickOffTime: 0x%llx\n", profile->KickOffTime.QuadPart);
        wprintf(L"PasswordLastSet: 0x%llx\n", profile->PasswordLastSet.QuadPart);
        wprintf(L"PasswordCanChange: 0x%llx\n", profile->PasswordCanChange.QuadPart);
        wprintf(L"PasswordMustChange: 0x%llx\n", profile->PasswordMustChange.QuadPart);
        wprintf(L"LogonScript: %s\n", ToWstring(profile->LogonScript).c_str());
        wprintf(L"HomeDirectory: %s\n", ToWstring(profile->HomeDirectory).c_str());
        wprintf(L"FullName: %s\n", ToWstring(profile->FullName).c_str());
        wprintf(L"ProfilePath: %s\n", ToWstring(profile->ProfilePath).c_str());
        wprintf(L"HomeDirectoryDrive: %s\n", ToWstring(profile->HomeDirectoryDrive).c_str());
        wprintf(L"LogonServer: %s\n", ToWstring(profile->LogonServer).c_str());
        wprintf(L"UserFlags: %u\n", profile->UserFlags);
    }

    NTSTATUS ret = CreateCmdProcessWithTokenW(token, username, password);

    LsaFreeReturnBuffer(profileBuffer);
    CloseHandle(token);
    return ret;
}


int wmain(int argc, wchar_t* argv[]) {
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
