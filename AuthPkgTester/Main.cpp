#include "LogonUser.hpp"


int wmain(int argc, wchar_t* argv[]) {
    if (argc == 1) {
        // query installed security packages
        LsaHandle lsa;
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

        // split "<domain>\<username>" strings
        size_t idx = username.find(L'\\');
        if (idx != username.npos) {
            domain = username.substr(0, idx);
            username = username.substr(idx + 1);
        }

        wprintf(L"\n");
        wprintf(L"Attempting local interactive logon against the %s authentication package...\n", authPkgName);
        std::vector<BYTE> authInfo = PrepareLogon_MSV1_0(domain, username, password); // Might need to replace with suitable authInfo for the selected authPkg

        HANDLE token = 0;
        PSID logonSid = nullptr;
#ifndef USE_LSA_LOGONUSER
        std::tie(token, logonSid) = LogonUserInteractive(username, password);
#else
        std::tie(token, logonSid) = LsaLogonUserInteractive(authPkgName, authInfo);
#endif

        wprintf(L"SUCCESS: User logon succeeded.\n");

        DWORD ret = CreateCmdProcessWithTokenW(token, username, logonSid);
        if (ret != STATUS_SUCCESS) {
            wprintf(L"ERROR: CreateProcessWithTokenW failed (%s)\n", ToString(ret).c_str());
        }
        else {
            wprintf(L"SUCCESS: CreateProcessWithTokenW succeeded.\n");
        }

        CloseHandle(token);
        FreeSid(logonSid);
    } else {
        wprintf(L"USAGE:\n");
        wprintf(L"  List security packages: AuthPkgTester.exe\n");
        wprintf(L"  Attempt MSV1_0 login: AuthPkgTester.exe [auth-package] <username> <password>\n");
    }
}
