#include <windows.h>
#include <wincred.h> // for CredUIPromptForWindowsCredentialsW
#include <iostream>

#pragma comment(lib, "Credui.lib")


/** Pre-populated credential fields. */
struct AuthInput {
    void* ptr = nullptr; // empty credential field
    ULONG size = 0;
};

struct AuthResult {
    AuthResult() = default;

    ~AuthResult() {
        // clear memory to avoid leaking secrets
        RtlSecureZeroMemory(ptr, size);
        // delete allocation
        CoTaskMemFree(ptr);
    }

    void* ptr = nullptr;   // [out]
    ULONG size = 0;        // [out]
};

struct TextString {
    TextString() = default;

    ~TextString() {
        // clear memory to avoid leaking secrets
        RtlSecureZeroMemory(ptr, sizeof(ptr)); // deliberately NOT using size member
    }

    wchar_t ptr[256] = {};
    ULONG size = (ULONG)std::size(ptr);
};

int main() {
    CREDUI_INFOW cred_info = {};
    cred_info.cbSize = sizeof(cred_info);
    cred_info.hwndParent = GetDesktopWindow();
    cred_info.pszCaptionText = L"Please sign in";
    cred_info.pszMessageText = L"Plase enter your credentials";

    // flags to enable display of all credential providers
    DWORD flags = CREDUIWIN_ENUMERATE_CURRENT_USER;
    //flags |= 0x80000000; // Windows Hello credentials packed in a smart card auth buffer

    AuthInput input;
    ULONG authPackage = 0;
    AuthResult result;

    DWORD res = CredUIPromptForWindowsCredentialsW(
        &cred_info,
        0, // don't display any error message
        &authPackage, // [in,out]
        input.ptr,
        input.size,
        &result.ptr,
        &result.size,
        nullptr, // disable "save" check box
        flags);

    if (res == ERROR_CANCELLED) {
        std::wcout << L"User canceled." << std::endl;
        return -1;
    }

    std::wcout << L"Credentials entered, but not checked." << std::endl;

    TextString username, password, domain;

    BOOL ok = CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,
        result.ptr, result.size,
        username.ptr, &username.size,
        domain.ptr, &domain.size,
        password.ptr, &password.size);
    if (!ok) {
        std::wcout << L"Unable to unpack credentials" << std::endl;
        return -1;
    }

    // TODO: Check credentials
}
