#include "LogonUser.hpp"


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


/** Alternative to GetCurrentProcessToken() with more privileges. */
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


struct Privilege {
    enum State {
        Missing,
        Enabled,
        Disabled,
    };

    const wchar_t* ToString() const {
        switch (state) {
        case Missing: return L"missing";
        case Enabled: return L"enabled";
        case Disabled: return L"disabled";
        default:
            abort();
        }
    }

    Privilege(HANDLE token, const wchar_t* privName) : token(token) {
        BOOL ok = LookupPrivilegeValueW(nullptr, privName, &value);
        assert(ok);

        // detect if privilege is enabled
        std::vector<BYTE> privilegesBuffer(1024, (BYTE)0);
        {
            DWORD privilegesLength = 0;
            ok = GetTokenInformation(token, TokenPrivileges, privilegesBuffer.data(), (DWORD)privilegesBuffer.size(), &privilegesLength);
            assert(ok);
            privilegesBuffer.resize(privilegesLength);
        }
        auto* tp = (TOKEN_PRIVILEGES*)privilegesBuffer.data();

        //wprintf(L"  Privilege count: %u.\n", tp->PrivilegeCount);
        for (size_t i = 0; i < tp->PrivilegeCount; i++) {
            const LUID_AND_ATTRIBUTES entry = tp->Privileges[i];
            bool match = (value.LowPart == entry.Luid.LowPart) && (value.HighPart == entry.Luid.HighPart);
            if (!match)
                continue;

            if (entry.Attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT))
                state = Enabled;
            else
                state = Disabled;
        }
    }

    void Modify(State s) {
        // https://learn.microsoft.com/nb-no/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
        TOKEN_PRIVILEGES tp = {
            .PrivilegeCount = 1,
        };
        tp.Privileges[0] = {
            .Luid = value,
            .Attributes = (s == Enabled) ? (DWORD)SE_PRIVILEGE_ENABLED : 0,
        };

        if (!AdjustTokenPrivileges(token, /*disableAll*/false, &tp, 0, nullptr, nullptr)) {
            DWORD err = GetLastError();
            wprintf(L"ERROR: AdjustTokenPrivileges failed (%s)\n", ::ToString(err).c_str());
            abort();
        }

        state = s;
    }

private:
    HANDLE token = 0;
public:
    LUID  value{};
    State state = Missing;
};

bool AdjustTokenPrivileges(HANDLE token) {
    {
        TOKEN_TYPE tokenType = {};
        DWORD tokenLen = 0;
        if (!GetTokenInformation(token, TokenType, &tokenType, sizeof(tokenType), &tokenLen))
            abort();

        wprintf(L"  TokenType: %s\n", (tokenType == TokenPrimary) ? L"Primary" : L"Impersonation");
    }

    Privilege IncreaseQuta(token, SE_INCREASE_QUOTA_NAME); // required by CreateProcessAsUser
    Privilege AssignPrimaryToken(token, SE_ASSIGNPRIMARYTOKEN_NAME); // may be required by CreateProcessAsUser
    Privilege Impersonate(token, SE_IMPERSONATE_NAME);     // required by CreateProcessWithToken

    wprintf(L"  SE_INCREASE_QUOTA_NAME privilege %s\n", IncreaseQuta.ToString());
    wprintf(L"  SE_ASSIGNPRIMARYTOKEN_NAME privilege %s\n", AssignPrimaryToken.ToString());
    wprintf(L"  SE_IMPERSONATE_NAME privilege %s\n", Impersonate.ToString());

    // enable disabled privileges
    if (IncreaseQuta.state == Privilege::Disabled) {
        wprintf(L"  Enabling SE_INCREASE_QUOTA_NAME...\n");
        IncreaseQuta.Modify(Privilege::Enabled);
    }
    if (AssignPrimaryToken.state == Privilege::Disabled) {
        wprintf(L"  Enabling SE_ASSIGNPRIMARYTOKEN_NAME...\n");
        AssignPrimaryToken.Modify(Privilege::Enabled);
    }
    if (Impersonate.state == Privilege::Disabled) {
        wprintf(L"  Enabling SE_IMPERSONATE_NAME...\n");
        Impersonate.Modify(Privilege::Enabled);
    }

    return true;
}


int wmain(int argc, wchar_t* argv[]) {
    AdjustTokenPrivileges(GetCurrentProcessTokenEx());

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
        std::wstring domain = L"";
        std::wstring username = argv[argIdx++];
        std::wstring password = argv[argIdx++];

        wprintf(L"\n");
        wprintf(L"Attempting local interactive logon against the %s authentication package...\n", authPkgName);
        std::vector<BYTE> authInfo;
        if (std::wstring(authPkgName) == MSV1_0_PACKAGE_NAMEW)
            authInfo = PrepareLogon_MSV1_0(domain, username, password);
        else
            authInfo = PrepareLogon_MSV1_0(domain, username, password); // TODO: Replace with suitable authInfo for the selected authPkg

        NTSTATUS ret = LsaLogonUserInteractive(lsa, authPkgName, authInfo, username, password);
        if (ret != STATUS_SUCCESS) {
            wprintf(L"ERROR: LsaLogonUser failed (%s)\n", ToString(ret).c_str());
        } else {
            wprintf(L"SUCCESS: User logon succeeded.\n");
        }
    } else {
        wprintf(L"USAGE:\n");
        wprintf(L"  List security packages: AuthPkgTester.exe\n");
        wprintf(L"  Attempt MSV1_0 login: AuthPkgTester.exe [auth-package] <username> <password>\n");
    }
}
