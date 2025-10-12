#pragma once


void PrintSecPkgCapabilities(unsigned long capabilities) {
    if (capabilities & SECPKG_FLAG_INTEGRITY)
        wprintf(L"FLAG_INTEGRITY |");
    if (capabilities & SECPKG_FLAG_PRIVACY)
        wprintf(L"FLAG_PRIVACY |");
    if (capabilities & SECPKG_FLAG_TOKEN_ONLY)
        wprintf(L"FLAG_TOKEN_ONLY |");
    if (capabilities & SECPKG_FLAG_DATAGRAM)
        wprintf(L"FLAG_DATAGRAM |");
    if (capabilities & SECPKG_FLAG_CONNECTION)
        wprintf(L"FLAG_CONNECTION |");
    if (capabilities & SECPKG_FLAG_MULTI_REQUIRED)
        wprintf(L"FLAG_MULTI_REQUIRED |");
    if (capabilities & SECPKG_FLAG_CLIENT_ONLY)
        wprintf(L"FLAG_CLIENT_ONLY |");
    if (capabilities & SECPKG_FLAG_EXTENDED_ERROR)
        wprintf(L"FLAG_EXTENDED_ERROR |");
    if (capabilities & SECPKG_FLAG_IMPERSONATION)
        wprintf(L"FLAG_IMPERSONATION |");
    if (capabilities & SECPKG_FLAG_ACCEPT_WIN32_NAME)
        wprintf(L"FLAG_ACCEPT_WIN32_NAME |");
    if (capabilities & SECPKG_FLAG_STREAM)
        wprintf(L"FLAG_STREAM |");
    if (capabilities & SECPKG_FLAG_NEGOTIABLE)
        wprintf(L"FLAG_NEGOTIABLE |");
    if (capabilities & SECPKG_FLAG_GSS_COMPATIBLE)
        wprintf(L"FLAG_GSS_COMPATIBLE |");
    if (capabilities & SECPKG_FLAG_LOGON)
        wprintf(L"FLAG_LOGON |");
    if (capabilities & SECPKG_FLAG_ASCII_BUFFERS)
        wprintf(L"FLAG_ASCII_BUFFERS |");
    if (capabilities & SECPKG_FLAG_FRAGMENT)
        wprintf(L"FLAG_FRAGMENT |");
    if (capabilities & SECPKG_FLAG_MUTUAL_AUTH)
        wprintf(L"FLAG_MUTUAL_AUTH |");
    if (capabilities & SECPKG_FLAG_DELEGATION)
        wprintf(L"FLAG_DELEGATION |");
    if (capabilities & SECPKG_FLAG_READONLY_WITH_CHECKSUM)
        wprintf(L"FLAG_READONLY_WITH_CHECKSUM |");
    if (capabilities & SECPKG_FLAG_RESTRICTED_TOKENS)
        wprintf(L"FLAG_RESTRICTED_TOKENS |");
    if (capabilities & SECPKG_FLAG_NEGO_EXTENDER)
        wprintf(L"FLAG_NEGO_EXTENDER |");
    if (capabilities & SECPKG_FLAG_NEGOTIABLE2)
        wprintf(L"FLAG_NEGOTIABLE2 |");
    if (capabilities & SECPKG_FLAG_APPCONTAINER_PASSTHROUGH)
        wprintf(L"FLAG_APPCONTAINER_PASSTHROUGH |");
    if (capabilities & SECPKG_FLAG_APPCONTAINER_CHECKS)
        wprintf(L"FLAG_APPCONTAINER_CHECKS |");
    if (capabilities & SECPKG_CALLFLAGS_APPCONTAINER)
        wprintf(L"CALLFLAGS_APPCONTAINER |");
    //if (capabilities & SECPKG_CALLFLAGS_AUTHCAPABLE)
    //    wprintf(L"CALLFLAGS_AUTHCAPABLE |");
    if (capabilities & SECPKG_CALLFLAGS_FORCE_SUPPLIED)
        wprintf(L"CALLFLAGS_FORCE_SUPPLIED |");
}

void PrintSecPkgInfo(const SecPkgInfoW& pkg) {
    wprintf(L"Package: %s\n", pkg.Name);

    wprintf(L"* Comment: %s\n", pkg.Comment);

    wprintf(L"* Capabilities: ");
    PrintSecPkgCapabilities(pkg.fCapabilities);
    wprintf(L"\n");
}
