#define SECURITY_WIN32 // required by sspi.h
#include <windows.h>
#include <sspi.h>
#include <iostream>

#pragma comment(lib, "Secur32.lib")


int wmain(int /*argc*/, wchar_t* /*argv*/[])
{
    ULONG package_count = 0;
    SecPkgInfoW* packages = nullptr;
    SECURITY_STATUS ret = EnumerateSecurityPackagesW(&package_count, &packages);
    if (ret != SEC_E_OK) {
        wprintf(L"ERROR: EnumerateSecurityPackagesW failed with error %u\n", ret);
        return -1;
    }

    wprintf(L"Installed security packages:\n");
    for (ULONG idx = 0; idx < package_count; idx++) {
        SecPkgInfoW& pkg = packages[idx];
        wprintf(L"* %s (%s)\n", pkg.Name, pkg.Comment);
    }

    FreeContextBuffer(packages);
}
