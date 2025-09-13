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

    wchar_t ptr[1536] = {}; // encoded PIN-code passwords have been observed to be >1200 chars
    ULONG size = (ULONG)std::size(ptr);
};

int main() {
    CREDUI_INFOW cred_info = {};
    cred_info.cbSize = sizeof(cred_info);
    cred_info.hwndParent = GetDesktopWindow();
    cred_info.pszCaptionText = L"Custom authentication";
    cred_info.pszMessageText = L"Plase enter your credentials";
    cred_info.hbmBanner = 0; // custom bitmap (max 320x60 pixels)

    // Enable display of all credential providers.
    // This will include Windows Hello and PIN athentication unless blocked by system policy.
    // REF: https://github.com/chromium/chromium/blob/main/chrome/browser/password_manager/password_manager_util_win.cc
    DWORD flags = CREDUIWIN_ENUMERATE_CURRENT_USER;

    AuthInput input; // empty
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
    if (res != ERROR_SUCCESS) {
        if (res == ERROR_CANCELLED) {
            wprintf(L"ERROR: User canceled.\n");
            return -1;
        } else {
            DWORD err = GetLastError();
            wprintf(L"CredUIPromptForWindowsCredentials failed (err=%u)\n", err);
            return -1;
        }
    }

    TextString username, password, domain;
    BOOL ok = CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,
        result.ptr, result.size,
        username.ptr, &username.size,
        domain.ptr, &domain.size,
        password.ptr, &password.size);
    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"Unable to unpack credentials (err=%u)\n", err);
        return -1;
    }

    wprintf(L"Provided credentials (not checked):\n");
    wprintf(L"Username: %s\n", username.ptr);
    wprintf(L"Password: %s\n", password.ptr);
    wprintf(L"Domain: %s\n", domain.ptr);

    // check credentials (confirmed to work for local accounts and PIN-codes)
    HANDLE token = 0;
    ok = LogonUserW(username.ptr, domain.ptr, password.ptr, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_LOGON_FAILURE) {
            wprintf(L"ERROR: The user name or password is incorrect.\n");
            return -1;
        } else if (err == ERROR_BAD_NETPATH) {
            wprintf(L"ERROR: The network path was not found.\n");
            return -2;
        } else {
            wprintf(L"ERROR: Other LogonUser error (err=%u)\n", err);
            return -2;
        }
    }

    wprintf(L"Authentication succeeded.\n");
    CloseHandle(token);
}
