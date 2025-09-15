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

struct SecureString {
    SecureString() = default;

    ~SecureString() {
        // clear memory to avoid leaking secrets
        RtlSecureZeroMemory(str.data(), str.size()); // deliberately NOT using size member
    }

    void Resize() {
        str.resize(size, L'\0');
    }

    operator const wchar_t* () const {
        return str.c_str();
    }

    std::wstring str;
    ULONG size = 0;
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
            wprintf(L"ERROR: CredUIPromptForWindowsCredentials failed (err=%u)\n", err);
            return -1;
        }
    }

    SecureString username, domain, password;
    {
        // determine buffer sizes
        BOOL ok = CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,
            result.ptr, result.size,
            nullptr, &username.size,
            nullptr, &domain.size,
            nullptr, &password.size);
        assert(!ok);

        username.Resize();
        domain.Resize();
        password.Resize();

        // get username, password & domain strings
        ok = CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,
            result.ptr, result.size,
            username.str.data(), &username.size,
            domain.str.data(), &domain.size,
            password.str.data(), &password.size);
        if (!ok) {
            DWORD err = GetLastError();
            wprintf(L"ERROR: CredUnPackAuthenticationBuffer failed (err=%u)\n", err);
            return -1;
        }
    }

    wprintf(L"Provided credentials (not checked):\n");
    wprintf(L"Username: %s\n", (const wchar_t*)username);
    wprintf(L"Domain:   %s\n", (const wchar_t*)domain);
    wprintf(L"Password: %s\n", (const wchar_t*)password);

    if (domain.str.empty()) {
        if (size_t idx = username.str.find(L'\\'); idx != std::wstring::npos) {
            // split usernae from domain
            domain.str = username.str.substr(0, idx);
            username.str = username.str.substr(idx + 1);
        }
    }

    // Check credentials (confirmed to work for local accounts and PIN-codes)
    // Failures are logged in the Event Viewer "Security" log with "Logon" category
    // TODO: Test if LsaLogonUser works better for domain accounts
    HANDLE token = 0;
    BOOL ok = LogonUserW(username, domain, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_LOGON_FAILURE) {
            wprintf(L"ERROR: The user name or password is incorrect.\n");
            return -1;
        } else if (err == ERROR_BAD_NETPATH) {
            wprintf(L"ERROR: The network path was not found (seem to happen for domain accounts).\n");
            return -2;
        } else {
            wprintf(L"ERROR: Other LogonUser error (err=%u)\n", err);
            return -2;
        }
    }

    wprintf(L"SUCCESS: Authentication succeeded.\n");
    CloseHandle(token);
}
