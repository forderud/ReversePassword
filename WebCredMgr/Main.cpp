#include <Windows.h>
#include <wincred.h>
#include <iostream>
#include <cassert>

/** Store credential in Windows Credential Manager. */
bool StoreCredential(const std::wstring& username, const std::wstring& secret) {
    CREDENTIALW cred{};
    cred.Flags = 0;
    cred.Type = CRED_TYPE_GENERIC;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE; // disable roaming
    cred.TargetName = const_cast<WCHAR*>(username.c_str());
    cred.CredentialBlob = reinterpret_cast<BYTE*>(const_cast<WCHAR*>(secret.data()));
    cred.CredentialBlobSize = (DWORD)secret.length()*sizeof(WCHAR);

    BOOL ok = CredWriteW(&cred, 0);
    return ok;
}

/** Load credential from Windows Credential Manager. */
bool LoadCredential(const std::wstring& username, /*out*/std::wstring& secret) {
    CREDENTIALW* cred = nullptr;
    BOOL ok = CredReadW(username.c_str(), CRED_TYPE_GENERIC, 0, &cred);
    if (!ok)
        return false;
    
    secret.assign(reinterpret_cast<WCHAR*>(cred->CredentialBlob), cred->CredentialBlobSize/sizeof(WCHAR));
    CredFree(cred);
    return true;
}


int main() {
    const WCHAR username[] = L"TestUser";

    bool ok = StoreCredential(username, L"Password123");
    if (!ok) {
        std::wcerr << L"Failed to store credential. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    std::wstring password;
    ok = LoadCredential(username, password);
    if (!ok) {
        std::wcerr << L"Failed to load credential. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    std::wcout << L"Credential loaded successfully!" << std::endl;
    std::wcout << L"Password: " << password << std::endl;

    return 0;
}
