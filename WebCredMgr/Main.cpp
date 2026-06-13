/** Simple utility for reading and writing to the Windows Credential Manager. */
#include <Windows.h>
#include <wincred.h>
#include <iostream>
#include <cassert>


/** Store credential in Windows Credential Manager. */
bool StoreCredential(const std::wstring& url, const std::wstring& username, const std::wstring& secret) {
    CREDENTIALW cred{};
    cred.Flags = 0;
    cred.Type = CRED_TYPE_GENERIC;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE; // disable network sync if domain joined
    cred.TargetName = const_cast<WCHAR*>(url.c_str());
    cred.UserName = const_cast<WCHAR*>(username.c_str());
    cred.CredentialBlob = reinterpret_cast<BYTE*>(const_cast<WCHAR*>(secret.data()));
    cred.CredentialBlobSize = (DWORD)secret.length()*sizeof(WCHAR);

    BOOL ok = CredWriteW(&cred, 0);
    return ok;
}

/** Load credential from Windows Credential Manager. */
bool LoadCredential(const std::wstring& url, /*out*/std::wstring& secret) {
    CREDENTIALW* cred = nullptr;
    BOOL ok = CredReadW(url.c_str(), CRED_TYPE_GENERIC, 0, &cred);
    if (!ok)
        return false;
    
    secret.assign(reinterpret_cast<WCHAR*>(cred->CredentialBlob), cred->CredentialBlobSize/sizeof(WCHAR));
    CredFree(cred);
    return true;
}


int wmain(int argc, wchar_t* argv[]) {
    // web addres to associate the credentals against
    const std::wstring url = L"https://myserver.com/";

    if (argc == 1) {
        // load credential
        std::wstring password;
        bool ok = LoadCredential(url, /*out*/password);
        if (!ok) {
            wprintf(L"Failed to load credential. Error code: %u\n", GetLastError());
            return 1;
        }

        wprintf(L"Credential loaded successfully!\n");
        wprintf(L"Password: %s\n", password.c_str());
    } else if (argc == 3) {
        // store/overwrite credential
        bool ok = StoreCredential(url, argv[1], argv[2]);
        if (!ok) {
            wprintf(L"Failed to store credential. Error code: %u\n", GetLastError());
            return 1;
        }

        wprintf(L"Credential stored successfully.\n");
    } else {
        wprintf(L"Usage load: %s \n", argv[0]);
        wprintf(L"Usage store: %s <username> <secret>\n", argv[0]);
        return 1;
    }

    return 0;
}
