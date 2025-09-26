#include <Windows.h>
#include <iostream>
#include <string>


int wmain(int argc, wchar_t* argv[])
{
    wprintf(L"Change password for a local account.\n");

    if (argc < 4) {
        wprintf(L"Usage: PasswordChanger.exe <username> <old-password> <new-password>\n");
        return -1;
    }

    std::wstring username = argv[1];
    std::wstring oldPwd = argv[2];
    std::wstring newPwd = argv[3];


    wprintf(L"ERROR: Not yet implemented");
    return -2;
}
