#include <cassert>
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

/** std::wstring extension that clears the buffer before destruction. */
struct SecureString : std::wstring {
    SecureString() = default;

    ~SecureString() {
        // clear memory to avoid leaking secrets
        RtlSecureZeroMemory(data(), size());
    }
};

int main() {
    AuthResult result;
    {
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
            }
            else {
                DWORD err = GetLastError();
                wprintf(L"ERROR: CredUIPromptForWindowsCredentials failed (err=%u)\n", err);
                return -1;
            }
        }
    }

    std::wstring username;
    SecureString password;
    {
        // determine buffer sizes
        DWORD username_len = 0, password_len = 0;
        BOOL ok = CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,
            result.ptr, result.size,
            nullptr, &username_len,
            nullptr, nullptr,
            nullptr, &password_len);
        assert(!ok);

        username.resize(username_len);
        password.resize(password_len);

        // get username, password & domain strings
        ok = CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,
            result.ptr, result.size,
            username.data(), &username_len,
            nullptr, nullptr,
            password.data(), &password_len);
        if (!ok) {
            DWORD err = GetLastError();
            wprintf(L"ERROR: CredUnPackAuthenticationBuffer failed (err=%u)\n", err);
            return -1;
        }
    }

    wprintf(L"Provided credentials (not checked):\n");
    wprintf(L"Username: %s\n", username.c_str());
    wprintf(L"Password: %s\n", password.c_str());

    std::wstring domain;
    if (size_t idx = username.find(L'\\'); idx != std::wstring::npos) {
        // split usernae from domain
        domain = username.substr(0, idx);
        username = username.substr(idx + 1);
    }

    // Check credentials (confirmed to work for local accounts, domain accounts and PIN-codes)
    // Failures are logged in the Event Viewer "Security" log with "Logon" category
    HANDLE token = 0;
    BOOL ok = LogonUserW(username.c_str(), domain.c_str(), password.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_LOGON_FAILURE) {
            wprintf(L"ERROR: The user name or password is incorrect.\n");
            return -1;
        } else {
            wprintf(L"ERROR: Other LogonUser error (err=%u)\n", err);
            return -2;
        }
    }

    wprintf(L"SUCCESS: Authentication succeeded.\n");
    CloseHandle(token);
}
