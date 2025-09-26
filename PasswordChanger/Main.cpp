#include <Windows.h>
#include <lm.h>
#include <iostream>
#include <string>

#pragma comment(lib, "netapi32.lib") // for NetUserChangePassword


int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"Change password for a local account.\n");
    wprintf(L"\n");

    if (argc < 4) {
        wprintf(L"Usage: PasswordChanger.exe <username> <old-password> <new-password>\n");
        return -1;
    }

    wchar_t* username = argv[1];
    wchar_t* oldPwd = argv[2];
    wchar_t* newPwd = argv[3];

    wprintf(L"Changing password for user %s...\n", username);

    NET_API_STATUS res = NetUserChangePassword(nullptr, username, oldPwd, newPwd);
    if (res != NERR_Success) {
        if (res == ERROR_ACCESS_DENIED)
            wprintf(L"ERROR: Access denied.\n");
        else if (res == ERROR_INVALID_PASSWORD)
            wprintf(L"ERROR: Invalid password.\n");
        else if (res == NERR_UserNotFound)
            wprintf(L"ERROR: User name not found.\n");
        else if (res == NERR_PasswordTooShort)
            wprintf(L"ERROR: Password too short.\n");
        else
            wprintf(L"ERROR: Password change failed with err %u\n", res);
        return -2;
    }

    wprintf(L"SUCCESS: Password changed\n");
    return 0;
}
