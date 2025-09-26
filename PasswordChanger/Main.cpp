#define SECURITY_WIN32

#include <Windows.h>
#include <lm.h>
#include <lmaccess.h>
#include <ntsecapi.h>
#include <sspi.h>
#include <iostream>
#include <string>

#pragma comment(lib, "Secur32.lib") // for ChangeAccountPasswordW
#pragma comment(lib, "netapi32.lib") // for NetUserChangePassword


int wmain(int argc, wchar_t* argv[])
{
    wprintf(L"Change password for a local account.\n");
    wprintf(L"\n");

    if (argc < 4) {
        wprintf(L"Usage: PasswordChanger.exe <username> <old-password> <new-password>\n");
        return -1;
    }

    std::wstring domain;
    std::wstring username = argv[1];
    std::wstring oldPwd = argv[2];
    std::wstring newPwd = argv[3];

#if 0
    std::wstring packageName = L"Negotiate"; // "Kerberos", "Negotiate", or "NTLM".
    BOOLEAN impersonating = false;

    SecBufferDesc output{};
    SecBuffer response{};
    DOMAIN_PASSWORD_INFORMATION dpi{};
    {
        // output must contain a single SECBUFFER_CHANGE_PASS_RESPONSE buffer
        response.BufferType = SECBUFFER_CHANGE_PASS_RESPONSE;
        response.cbBuffer = sizeof(dpi);
        response.pvBuffer = &dpi;

        output.ulVersion = SECBUFFER_VERSION;
        output.cBuffers = 1; // one buffer
        output.pBuffers = &response;
    }

    SECURITY_STATUS res = ChangeAccountPasswordW(packageName.data(), domain.data(), username.data(), oldPwd.data(), newPwd.data(), impersonating, 0, &output);
    if (res != SEC_E_OK) {
        if (res == SEC_E_SECPKG_NOT_FOUND)
            wprintf(L"ERROR: Security package not found.\n");
        else if (res == SEC_E_INVALID_TOKEN)
            wprintf(L"ERROR: Invalid token.\n");
        else
            wprintf(L"ERROR: Password change failed with err 0x%x\n", res);
        return -2;
    }
#else
    NET_API_STATUS res = NetUserChangePassword(domain.c_str(), username.c_str(), oldPwd.c_str(), newPwd.c_str());
    if (res != NERR_Success) {
        if (res == NERR_UserNotFound)
            wprintf(L"ERROR: User name not found.\n");
        else
            wprintf(L"ERROR: Password change failed with err %u\n", res);
        return -2;
    }
#endif

    wprintf(L"SUCCESS: Password changed\n");
    return 0;
}
