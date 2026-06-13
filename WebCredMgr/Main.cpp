#include <Windows.h>
#include <wincred.h>
#include <iostream>
#include <cassert>

//#pragma comment(lib, "Advapi32.lib") // CredReadW


bool StoreCredential(const std::wstring& username, const std::wstring& password) {
    CREDENTIALW cred{};
    cred.Flags = 0;
    cred.Type = CRED_TYPE_GENERIC;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE; // disable roaming
    cred.TargetName = const_cast<WCHAR*>(username.c_str());
    cred.CredentialBlob = reinterpret_cast<BYTE*>(const_cast<WCHAR*>(password.data()));
    cred.CredentialBlobSize = (DWORD)password.length()*sizeof(WCHAR);

    BOOL ok = CredWriteW(&cred, 0);
    return ok;
}

bool LoadCredential(const std::wstring& username, /*out*/std::wstring& password) {
    CREDENTIALW* cred = nullptr;
    BOOL ok = CredReadW(username.c_str(), CRED_TYPE_GENERIC, 0, &cred);
    if (!ok)
        return false;
    
    password.assign(reinterpret_cast<WCHAR*>(cred->CredentialBlob), cred->CredentialBlobSize / sizeof(WCHAR));
    CredFree(cred);
    return true;
}


int main() {
    const WCHAR username[] = L"TestUser";

    bool ok = StoreCredential(username, L"Password123");
    assert(ok);

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
