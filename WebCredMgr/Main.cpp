/** Simple utility for reading and writing to the Windows Credential Manager. */
#include <Windows.h>
#include <wincred.h>
#include <iostream>
#include <cassert>


/** Store credential in Windows Credential Manager. */
bool StoreCredential(const std::wstring& target, const std::wstring& username, const std::wstring& secret) {
    CREDENTIALW cred{};
    cred.Flags = 0;
    cred.Type = CRED_TYPE_GENERIC;
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE; // disable network sync if domain joined
    cred.TargetName = const_cast<WCHAR*>(target.c_str());
    cred.UserName = const_cast<WCHAR*>(username.c_str());
    cred.CredentialBlob = reinterpret_cast<BYTE*>(const_cast<WCHAR*>(secret.data()));
    cred.CredentialBlobSize = (DWORD)secret.length()*sizeof(WCHAR);

    BOOL ok = CredWriteW(&cred, 0);
    return ok;
}

/** Load credential from Windows Credential Manager. */
bool LoadCredential(const std::wstring& target, /*out*/std::wstring& username ,/*out*/std::wstring& secret) {
    CREDENTIALW* cred = nullptr;
    BOOL ok = CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &cred); // or CRED_TYPE_DOMAIN_PASSWORD
    if (!ok)
        return false;

    username = cred->UserName;
    secret.assign(reinterpret_cast<WCHAR*>(cred->CredentialBlob), cred->CredentialBlobSize/sizeof(WCHAR)); // might not be null-terminated
    CredFree(cred);
    return true;
}


void PrintUsage() {
    wprintf(L"Usage:\n");
    wprintf(L"  Load stored credential:     WebCredMgr.exe <TargetName>\n");
    wprintf(L"  Store/overwrite credential: WebCredMgr.exe <TargetName> <UserName> <Secret>\n");
}


int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    } 
    
    std::wstring url = argv[1];
    
    if (argc == 2) {
        // load credential associated with a target/URL
        std::wstring username, password;
        bool ok = LoadCredential(url, /*out*/username, /*out*/password);
        if (!ok) {
            wprintf(L"Failed to load credential. Error code: %u\n", GetLastError());
            return 1;
        }

        wprintf(L"Credential loaded successfully!\n");
        wprintf(L"Username: %s\n", username.c_str());
        wprintf(L"Password: %s\n", password.c_str());
    } else if (argc == 4) {
        // store/overwrite credential
        bool ok = StoreCredential(url, argv[2], argv[3]);
        if (!ok) {
            wprintf(L"Failed to store credential. Error code: %u\n", GetLastError());
            return 1;
        }

        wprintf(L"Credential stored successfully.\n");
    } else {
        PrintUsage();
        return 1;
    }

    return 0;
}
