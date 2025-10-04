#define SECURITY_WIN32 // required by sspi.h
#include <windows.h>
#include <sspi.h>
#include <security.h> // for NEGOSSP_NAME_A, MICROSOFT_KERBEROS_NAME_A
#include <NTSecAPI.h> // for MSV1_0_PACKAGE_NAME
#include <SubAuth.h>
#include <cassert>
#include <iostream>

#pragma comment(lib, "Secur32.lib")


void PrintCapabilities(unsigned long capabilities) {
    if (capabilities | SECPKG_FLAG_INTEGRITY)
        wprintf(L"FLAG_INTEGRITY |");
    if (capabilities | SECPKG_FLAG_PRIVACY)
        wprintf(L"FLAG_PRIVACY |");
    if (capabilities | SECPKG_FLAG_TOKEN_ONLY)
        wprintf(L"FLAG_TOKEN_ONLY |");
    if (capabilities | SECPKG_FLAG_DATAGRAM)
        wprintf(L"FLAG_DATAGRAM |");
    if (capabilities | SECPKG_FLAG_CONNECTION)
        wprintf(L"FLAG_CONNECTION |");
    if (capabilities | SECPKG_FLAG_MULTI_REQUIRED)
        wprintf(L"FLAG_MULTI_REQUIRED |");
    if (capabilities | SECPKG_FLAG_CLIENT_ONLY)
        wprintf(L"FLAG_CLIENT_ONLY |");
    if (capabilities | SECPKG_FLAG_EXTENDED_ERROR)
        wprintf(L"FLAG_EXTENDED_ERROR |");
    if (capabilities | SECPKG_FLAG_IMPERSONATION)
        wprintf(L"FLAG_IMPERSONATION |");
    if (capabilities | SECPKG_FLAG_ACCEPT_WIN32_NAME)
        wprintf(L"FLAG_ACCEPT_WIN32_NAME |");
    if (capabilities | SECPKG_FLAG_STREAM)
        wprintf(L"FLAG_STREAM |");
    if (capabilities | SECPKG_FLAG_NEGOTIABLE)
        wprintf(L"FLAG_NEGOTIABLE |");
    if (capabilities | SECPKG_FLAG_GSS_COMPATIBLE)
        wprintf(L"FLAG_GSS_COMPATIBLE |");
    if (capabilities | SECPKG_FLAG_LOGON)
        wprintf(L"FLAG_LOGON |");
    if (capabilities | SECPKG_FLAG_ASCII_BUFFERS)
        wprintf(L"FLAG_ASCII_BUFFERS |");
    if (capabilities | SECPKG_FLAG_FRAGMENT)
        wprintf(L"FLAG_FRAGMENT |");
    if (capabilities | SECPKG_FLAG_MUTUAL_AUTH)
        wprintf(L"FLAG_MUTUAL_AUTH |");
    if (capabilities | SECPKG_FLAG_DELEGATION)
        wprintf(L"FLAG_DELEGATION |");
    if (capabilities | SECPKG_FLAG_READONLY_WITH_CHECKSUM)
        wprintf(L"FLAG_READONLY_WITH_CHECKSUM |");
    if (capabilities | SECPKG_FLAG_RESTRICTED_TOKENS)
        wprintf(L"FLAG_RESTRICTED_TOKENS |");
    if (capabilities | SECPKG_FLAG_NEGO_EXTENDER)
        wprintf(L"FLAG_NEGO_EXTENDER |");
    if (capabilities | SECPKG_FLAG_NEGOTIABLE2)
        wprintf(L"FLAG_NEGOTIABLE2 |");
    if (capabilities | SECPKG_FLAG_APPCONTAINER_PASSTHROUGH)
        wprintf(L"FLAG_APPCONTAINER_PASSTHROUGH |");
    if (capabilities | SECPKG_FLAG_APPCONTAINER_CHECKS)
        wprintf(L"FLAG_APPCONTAINER_CHECKS |");
    if (capabilities | SECPKG_CALLFLAGS_APPCONTAINER)
        wprintf(L"CALLFLAGS_APPCONTAINER |");
    //if (capabilities | SECPKG_CALLFLAGS_AUTHCAPABLE)
    //    wprintf(L"CALLFLAGS_AUTHCAPABLE |");
    if (capabilities | SECPKG_CALLFLAGS_FORCE_SUPPLIED)
        wprintf(L"CALLFLAGS_FORCE_SUPPLIED |");
}

void PrintPackageInfo(const SecPkgInfoA& pkg) {
    wprintf(L"Package: %hs\n", pkg.Name);

    wprintf(L"* Comment: %hs\n", pkg.Comment);

    wprintf(L"* Capabilities: ");
    PrintCapabilities(pkg.fCapabilities);
    wprintf(L"\n");
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

ULONG GetAuthPackage(LsaHandle& lsa, const char* name) {
    LSA_STRING lsa_name{};
    lsa_name.Buffer = (char*)name;
    lsa_name.Length = (USHORT)strlen(name);
    lsa_name.MaximumLength = lsa_name.Length;

    ULONG authPkg = 0;
    NTSTATUS status = LsaLookupAuthenticationPackage(lsa, &lsa_name, &authPkg);
    if (status != STATUS_SUCCESS) {
        wprintf(L"ERROR: LsaLookupAuthenticationPackage failed with err: %u", status);
        abort();
    }

    return authPkg;
}


int wmain(int /*argc*/, wchar_t* /*argv*/[]) {
    ULONG package_count = 0;
    SecPkgInfoA* packages = nullptr;
    SECURITY_STATUS ret = EnumerateSecurityPackagesA(&package_count, &packages);
    if (ret != SEC_E_OK) {
        wprintf(L"ERROR: EnumerateSecurityPackagesW failed with error %u\n", ret);
        return -1;
    }

    LsaHandle lsa;

    wprintf(L"Installed security packages:\n");
    for (ULONG idx = 0; idx < package_count; idx++) {
        SecPkgInfoA& pkg = packages[idx];
        wprintf(L"\n");
        PrintPackageInfo(pkg);

        ULONG authPkg = GetAuthPackage(lsa, pkg.Name);
        wprintf(L"  AuthPkgID: %u\n", authPkg);
    }

    wprintf(L"\n");
    wprintf(L"Predefined security packages:\n");
    const char* predefined_packages[] = { NEGOSSP_NAME_A, MICROSOFT_KERBEROS_NAME_A, MSV1_0_PACKAGE_NAME };
    for (const char* package : predefined_packages) {
        ULONG authPkg = GetAuthPackage(lsa, package);
        wprintf(L"\n");
        wprintf(L"* Package: %hs\n", package);
        wprintf(L"  AuthPkgID: %u\n", authPkg);
    }

    FreeContextBuffer(packages);
}
