#define SECURITY_WIN32

#include <Windows.h>
#include <ntsecapi.h>
#include <sspi.h>
#include <iostream>
#include <string>

#pragma comment(lib, "Secur32.lib") // for ChangeAccountPasswordW


int wmain(int argc, wchar_t* argv[])
{
    wprintf(L"Change password for a local account.\n");

    if (argc < 4) {
        wprintf(L"Usage: PasswordChanger.exe <username> <old-password> <new-password>\n");
        return -1;
    }

    std::wstring packageName = L"Negotiate"; // "Kerberos", "Negotiate", or "NTLM".
    std::wstring domain;
    std::wstring username = argv[1];
    std::wstring oldPwd = argv[2];
    std::wstring newPwd = argv[3];

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

    wprintf(L"SUCCESS: Password changed\n");
    return 0;
}
