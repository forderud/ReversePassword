#include "Bluetooth.hpp"
#include <subauth.h>

#ifdef _WINDLL

LARGE_INTEGER InfiniteFuture() {
    LARGE_INTEGER val{};
    val.HighPart = 0x7FFFFFFF; // signed
    val.LowPart = 0xFFFFFFFF; // unsigned
    return val;
}

// exported symbols
#pragma comment( linker, "/export:Msv1_0SubAuthenticationRoutine" )
#pragma comment( linker, "/export:Msv1_0SubAuthenticationFilter" )


NTSTATUS SubAuthentication_impl(
    IN NETLOGON_LOGON_INFO_CLASS LogonLevel,
    IN NETLOGON_LOGON_IDENTITY_INFO* LogonInformation,
    IN ULONG Flags,
    IN PUSER_ALL_INFORMATION UserAll,
    OUT PULONG WhichFields,
    OUT PULONG UserFlags,
    OUT PBOOLEAN Authoritative,
    OUT PLARGE_INTEGER LogoffTime,
    OUT PLARGE_INTEGER KickoffTime)
{
    LogonLevel; // normally NetlogonInteractiveInformation
    LogonInformation;
    Flags;   // (MSV1_0_PASSTHRU, MSV1_0_GUEST_LOGON)
    UserAll; // user parameter struct

    *WhichFields = 0; // fields to write back to SAM on success (USER_ALL_PARAMETERS)
    *UserFlags = 0;   // (LOGON_GUEST, LOGON_NOENCRYPTION)
    *Authoritative = TRUE;           // returned to original caller
    *LogoffTime = InfiniteFuture();  // no limit
    *KickoffTime = InfiniteFuture(); // never kickoff

    if (HasBlueTooth())
        return STATUS_ACCOUNT_LOCKED_OUT; // block authentication if Bluetooth is enabled
    else
        return STATUS_SUCCESS;
}


/** Client/server authentication entry */
NTSTATUS NTAPI Msv1_0SubAuthenticationRoutine(
    IN NETLOGON_LOGON_INFO_CLASS LogonLevel,
    IN PVOID LogonInformation,
    IN ULONG Flags,
    IN PUSER_ALL_INFORMATION UserAll,
    OUT PULONG WhichFields,
    OUT PULONG UserFlags,
    OUT PBOOLEAN Authoritative,
    OUT PLARGE_INTEGER LogoffTime,
    OUT PLARGE_INTEGER KickoffTime)
{
    return SubAuthentication_impl(LogonLevel, (NETLOGON_LOGON_IDENTITY_INFO*)LogonInformation, Flags, UserAll, WhichFields, UserFlags, Authoritative, LogoffTime, KickoffTime);
}

/** User logon authentication entry */
NTSTATUS NTAPI Msv1_0SubAuthenticationFilter(
    IN NETLOGON_LOGON_INFO_CLASS LogonLevel,
    IN PVOID LogonInformation,
    IN ULONG Flags,
    IN PUSER_ALL_INFORMATION UserAll,
    OUT PULONG WhichFields,
    OUT PULONG UserFlags,
    OUT PBOOLEAN Authoritative,
    OUT PLARGE_INTEGER LogoffTime,
    OUT PLARGE_INTEGER KickoffTime )
{
    return SubAuthentication_impl(LogonLevel, (NETLOGON_LOGON_IDENTITY_INFO*)LogonInformation, Flags, UserAll, WhichFields, UserFlags, Authoritative, LogoffTime, KickoffTime);
}

#else

/** Test code if building as EXE */
int wmain(int /*argc*/, wchar_t* /*argv*/[]) {
    wprintf(L"BlueTooth detection...\n");

    bool btPresent = HasBlueTooth();
    if (btPresent)
        wprintf(L"SUCCESS: BlueTooth detected.\n");
    else
        wprintf(L"FAILURE: BlueTooth not detected.\n");
}

#endif
