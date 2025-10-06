#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#define SECURITY_WIN32 // required by sspi.h
#include <sspi.h>
#include <NTSecAPI.h>  // for LSA_STRING
#include <ntsecpkg.h>  // for LSA_DISPATCH_TABLE
#include <cassert>
#include <fstream>

#define USE_SECPKG_FUNCTION_TABLE

// exported symbols
// "DllMain" implicitly exported
#if 1
  #pragma comment(linker, "/export:SpLsaModeInitialize")
#else
  // https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-functions#functions-implemented-by-authentication-packages
  #pragma comment(linker, "/export:LsaApCallPackage" )
  #pragma comment(linker, "/export:LsaApCallPackagePassthrough" )
  #pragma comment(linker, "/export:LsaApCallPackageUntrusted" )
  #pragma comment(linker, "/export:LsaApInitializePackage" )
  #pragma comment(linker, "/export:LsaApLogonTerminated" )
  #pragma comment(linker, "/export:LsaApLogonUser" )
  #pragma comment(linker, "/export:LsaApLogonUserEx" )
  #pragma comment(linker, "/export:LsaApLogonUserEx2" )
#endif

#ifdef USE_SECPKG_FUNCTION_TABLE
  LSA_SECPKG_FUNCTION_TABLE FunctionTable;
#else
  LSA_DISPATCH_TABLE FunctionTable;
#endif

#include "Utils.hpp"


// LSA calls LsaApInitializePackage() when loading AuthPkg DLL
extern "C"
NTSTATUS LsaApInitializePackage(ULONG AuthenticationPackageId,
    LSA_DISPATCH_TABLE* lsaDispatchTable,
    LSA_STRING* Database,
    LSA_STRING* Confidentiality,
    LSA_STRING** AuthenticationPackageName
) {
    LogMessage("LsaApInitializePackage");
    AuthenticationPackageId;
    assert(!Database);
    assert(!Confidentiality);
    
#ifndef USE_SECPKG_FUNCTION_TABLE
    FunctionTable = *lsaDispatchTable; // copy function pointer table
#endif
    *AuthenticationPackageName = CreateLsaString("CustomAuthPkg"); // freed by caller

    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

extern "C"
NTSTATUS NTAPI SpInitialize(ULONG_PTR PackageId, SECPKG_PARAMETERS* Parameters, LSA_SECPKG_FUNCTION_TABLE* functionTable) {
    LogMessage("SpInitialize");
    PackageId;
    Parameters;
#ifdef USE_SECPKG_FUNCTION_TABLE
    FunctionTable = *functionTable; // copy function pointer table
#endif

    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

extern "C"
NTSTATUS NTAPI SpShutDown() {
    LogMessage("SpShutDown");
    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

extern "C"
NTSTATUS NTAPI SpGetInfo(SecPkgInfoW* PackageInfo) {
    LogMessage("SpGetInfo");

    // return security package metadata
    PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
    PackageInfo->wVersion = 1;
    PackageInfo->wRPCID = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = 0;
    PackageInfo->Name = (wchar_t*)L"CustomAuthPkg";
    PackageInfo->Comment = (wchar_t*)L"Custom security package for testing";

    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

NTSTATUS LsaApLogonUserEx2_impl(
    PLSA_CLIENT_REQUEST ClientRequest,
    SECURITY_LOGON_TYPE LogonType,
    VOID* ProtocolSubmitBuffer,
    VOID* ClientBufferBase,
    ULONG SubmitBufferSize,
    VOID** ProfileBuffer,
    ULONG* ProfileBufferSize,
    LUID* LogonId,
    NTSTATUS* SubStatus,
    LSA_TOKEN_INFORMATION_TYPE* TokenInformationType,
    VOID** TokenInformation,
    LSA_UNICODE_STRING** AccountName,
    LSA_UNICODE_STRING** AuthenticatingAuthority,
    LSA_UNICODE_STRING** MachineName,
    SECPKG_PRIMARY_CRED* PrimaryCredentials,
    SECPKG_SUPPLEMENTAL_CRED_ARRAY** SupplementalCredentials)
{
    // input arguments
    ClientRequest;
    LogMessage("  LogonType: %i", LogonType); // Interactive=2
    LogMessage("  ProtocolSubmitBuffer: 0x%p", ProtocolSubmitBuffer);
    LogMessage("  ClientBufferBase: 0x%p", ClientBufferBase);
    LogMessage("  ProtocolSubmitBuffer size: %i", SubmitBufferSize);

    if (LogonType != Interactive) {
        LogMessage("  return STATUS_NOT_IMPLEMENTED (unsupported LogonType)");
        return STATUS_NOT_IMPLEMENTED;
    }

    // assign output arguments
    *ProfileBuffer = nullptr; // TODO: implement BuildInteractiveProfileBuffer
    *ProfileBufferSize = 0;

    {
        // assign "LogonId" output argument
        if (!AllocateLocallyUniqueId(LogonId)) {
            LogMessage("  ERROR: AllocateLocallyUniqueId failed");
            return STATUS_FAIL_FAST_EXCEPTION;
        }
        NTSTATUS status = FunctionTable.CreateLogonSession(LogonId);
        if (status != STATUS_SUCCESS) {
            LogMessage("  ERROR: CreateLogonSession failed with err: 0x%x", status);
            return status;
        }

        LogMessage("  LogonId: LowPart=%x , HighPart:%x", LogonId->LowPart, LogonId->HighPart);
    }

    *SubStatus = STATUS_SUCCESS; // reason for error
    *TokenInformationType = LsaTokenInformationV1;
    *TokenInformation = nullptr;
    {
        // assign "AccountName" output argument
        auto* logonInfo = (MSV1_0_INTERACTIVE_LOGON*)ProtocolSubmitBuffer;
        if (SubmitBufferSize < sizeof(MSV1_0_INTERACTIVE_LOGON)) {
            LogMessage("  ERROR: SubmitBufferSize too small");
            return STATUS_INVALID_PARAMETER;
        }

        auto* username = (const wchar_t*)((BYTE*)logonInfo + (size_t)logonInfo->UserName.Buffer); // make pointer absolute
        LogMessage("  AccountName: %ls", username);
        *AccountName = CreateLsaUnicodeString(username, logonInfo->UserName.Length); // mandatory
    }

    if (AuthenticatingAuthority) {
        // assign "AuthenticatingAuthority" output argument
        auto* logonInfo = (MSV1_0_INTERACTIVE_LOGON*)ProtocolSubmitBuffer;
        auto* domainname = (const wchar_t*)((BYTE*)logonInfo + (size_t)logonInfo->LogonDomainName.Buffer); // make pointer absolute

        *AuthenticatingAuthority = (LSA_UNICODE_STRING*)FunctionTable.AllocateLsaHeap(sizeof(LSA_UNICODE_STRING));

        if (logonInfo->LogonDomainName.Length > 0) {
            *AuthenticatingAuthority = CreateLsaUnicodeString(domainname, logonInfo->LogonDomainName.Length);
        } else {
            **AuthenticatingAuthority = {
                .Length = 0,
                .MaximumLength = 0,
                .Buffer = nullptr,
            };
        }
    }

    if (MachineName) {
        // assign "MachineName" output argument
        wchar_t computerNameBuf[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD computerNameSize = ARRAYSIZE(computerNameBuf);
        if (!GetComputerNameW(computerNameBuf, &computerNameSize)) {
            LogMessage("  return STATUS_INTERNAL_ERROR (GetComputerNameW failed)");
            return STATUS_INTERNAL_ERROR;
        }

        LogMessage("  MachineName: %ls", computerNameBuf);
        *MachineName = CreateLsaUnicodeString(computerNameBuf, (USHORT)computerNameSize*sizeof(wchar_t));
    }

    if (PrimaryCredentials)
        *PrimaryCredentials = {};

    if (SupplementalCredentials)
        *SupplementalCredentials = nullptr;

    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

extern "C"
NTSTATUS LsaApLogonUser(
    PLSA_CLIENT_REQUEST ClientRequest,
    SECURITY_LOGON_TYPE LogonType,
    VOID* AuthenticationInformation,
    VOID* ClientAuthenticationBase,
    ULONG AuthenticationInformationLength,
    VOID** ProfileBuffer,
    ULONG* ProfileBufferLength,
    LUID* LogonId,
    NTSTATUS* SubStatus,
    LSA_TOKEN_INFORMATION_TYPE* TokenInformationType,
    VOID** TokenInformation,
    LSA_UNICODE_STRING** AccountName,
    LSA_UNICODE_STRING** AuthenticatingAuthority)
{
    LogMessage("LsaApLogonUser");

    return LsaApLogonUserEx2_impl(ClientRequest, LogonType, AuthenticationInformation, ClientAuthenticationBase, AuthenticationInformationLength,
        ProfileBuffer, ProfileBufferLength, LogonId, SubStatus, TokenInformationType, TokenInformation, AccountName, AuthenticatingAuthority, nullptr, nullptr, nullptr);
}

extern "C"
NTSTATUS LsaApLogonUserEx(
    PLSA_CLIENT_REQUEST ClientRequest,
    SECURITY_LOGON_TYPE LogonType,
    VOID* AuthenticationInformation,
    VOID* ClientAuthenticationBase,
    ULONG AuthenticationInformationLength,
    VOID** ProfileBuffer,
    ULONG* ProfileBufferLength,
    LUID* LogonId,
    NTSTATUS* SubStatus,
    LSA_TOKEN_INFORMATION_TYPE* TokenInformationType,
    VOID** TokenInformation,
    PUNICODE_STRING* AccountName,
    PUNICODE_STRING* AuthenticatingAuthority,
    PUNICODE_STRING* MachineName)
{
    LogMessage("LsaApLogonUserEx");

    return LsaApLogonUserEx2_impl(ClientRequest, LogonType, AuthenticationInformation, ClientAuthenticationBase, AuthenticationInformationLength,
        ProfileBuffer, ProfileBufferLength, LogonId, SubStatus, TokenInformationType, TokenInformation, AccountName, AuthenticatingAuthority, MachineName, nullptr, nullptr);
}

extern "C"
NTSTATUS LsaApLogonUserEx2(
    PLSA_CLIENT_REQUEST ClientRequest,
    SECURITY_LOGON_TYPE LogonType,
    VOID* ProtocolSubmitBuffer,
    VOID* ClientBufferBase,
    ULONG SubmitBufferSize,
    VOID** ProfileBuffer,
    ULONG* ProfileBufferSize,
    LUID* LogonId,
    NTSTATUS* SubStatus,
    LSA_TOKEN_INFORMATION_TYPE* TokenInformationType,
    VOID** TokenInformation,
    PUNICODE_STRING* AccountName,
    PUNICODE_STRING* AuthenticatingAuthority,
    PUNICODE_STRING* MachineName,
    SECPKG_PRIMARY_CRED* PrimaryCredentials,
    SECPKG_SUPPLEMENTAL_CRED_ARRAY** SupplementalCredentials)
{
    LogMessage("LsaApLogonUserEx2");

    return LsaApLogonUserEx2_impl(ClientRequest, LogonType, ProtocolSubmitBuffer, ClientBufferBase, SubmitBufferSize,
        ProfileBuffer, ProfileBufferSize, LogonId, SubStatus, TokenInformationType, TokenInformation, AccountName, AuthenticatingAuthority, MachineName, PrimaryCredentials, SupplementalCredentials);
}

extern "C"
NTSTATUS LsaApCallPackage(PLSA_CLIENT_REQUEST ClientRequest,
    VOID* ProtocolSubmitBuffer,
    VOID* ClientBufferBase,
    ULONG SubmitBufferLength,
    VOID** ProtocolReturnBuffer,
    ULONG* ReturnBufferLength,
    NTSTATUS* ProtocolStatus)
{
    LogMessage("LsaApCallPackage");
    ClientRequest;
    ProtocolSubmitBuffer;
    ClientBufferBase;
    SubmitBufferLength;
    ProtocolReturnBuffer;
    ReturnBufferLength;
    ProtocolStatus;
    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

extern "C"
void LsaApLogonTerminated(LUID* LogonId) {
    LogMessage("LsaApLogonTerminated");
    LogonId;
    LogMessage("  return");
}

extern "C"
NTSTATUS LsaApCallPackageUntrusted(
    PLSA_CLIENT_REQUEST ClientRequest,
    VOID*               ProtocolSubmitBuffer,
    VOID*               ClientBufferBase,
    ULONG               SubmitBufferLength,
    VOID** ProtocolReturnBuffer,
    ULONG*              ReturnBufferLength,
    NTSTATUS*           ProtocolStatus)
{
    LogMessage("LsaApCallPackageUntrusted");
    ClientRequest;
    ProtocolSubmitBuffer;
    ClientBufferBase;
    SubmitBufferLength;
    ProtocolReturnBuffer;
    ReturnBufferLength;
    ProtocolStatus;
    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

extern "C"
NTSTATUS LsaApCallPackagePassthrough(
    PLSA_CLIENT_REQUEST ClientRequest,
    VOID* ProtocolSubmitBuffer,
    VOID* ClientBufferBase,
    ULONG SubmitBufferLength,
    VOID** ProtocolReturnBuffer,
    ULONG* ReturnBufferLength,
    NTSTATUS* ProtocolStatus)
{
    LogMessage("LsaApCallPackagePassthrough");
    ClientRequest;
    ProtocolSubmitBuffer;
    ClientBufferBase;
    SubmitBufferLength;
    ProtocolReturnBuffer;
    ReturnBufferLength;
    ProtocolStatus;
    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}


SECPKG_FUNCTION_TABLE SecurityPackageFunctionTable = {
    .InitializePackage = LsaApInitializePackage,
    .LogonUser = LsaApLogonUser,
    .CallPackage = LsaApCallPackage,
    .LogonTerminated = LsaApLogonTerminated,
    .CallPackageUntrusted = LsaApCallPackageUntrusted,
    .CallPackagePassthrough = LsaApCallPackagePassthrough,
    .LogonUserEx = LsaApLogonUserEx,
    .LogonUserEx2 = LsaApLogonUserEx2,
    .Initialize = SpInitialize,
    .Shutdown = SpShutDown,
    .GetInfo = SpGetInfo,

    .AcceptCredentials = nullptr,
    .AcquireCredentialsHandle = nullptr,
    .QueryCredentialsAttributes = nullptr,
    .FreeCredentialsHandle = nullptr,
    .SaveCredentials = nullptr,
    .GetCredentials = nullptr,
    .DeleteCredentials = nullptr,
    .InitLsaModeContext = nullptr,
    .AcceptLsaModeContext = nullptr,
    .DeleteContext = nullptr,
    .ApplyControlToken = nullptr,
    .GetUserInfo = nullptr,
    .GetExtendedInformation = nullptr,
    .QueryContextAttributes = nullptr,
    .AddCredentialsW = nullptr,
    .SetExtendedInformation = nullptr,
    .SetContextAttributes = nullptr,
    .SetCredentialsAttributes = nullptr,
    .ChangeAccountPassword = nullptr,
    .QueryMetaData = nullptr,
    .ExchangeMetaData = nullptr,
    .GetCredUIContext = nullptr,
    .UpdateCredentials = nullptr,
    .ValidateTargetInfo = nullptr,
    .PostLogonUser = nullptr,
    .GetRemoteCredGuardLogonBuffer = nullptr,
    .GetRemoteCredGuardSupplementalCreds = nullptr,
    .GetTbalSupplementalCreds = nullptr,
    .LogonUserEx3 = nullptr,
    .PreLogonUserSurrogate = nullptr,
    .PostLogonUserSurrogate = nullptr,
    .ExtractTargetInfo = nullptr,
};

// LSA calls SpLsaModeInitialize() when loading SSP DLL
extern "C"
NTSTATUS NTAPI SpLsaModeInitialize(ULONG LsaVersion, ULONG* PackageVersion, SECPKG_FUNCTION_TABLE** ppTables, ULONG* pcTables) {
    LogMessage("SpLsaModeInitialize");
    LsaVersion;
    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables = &SecurityPackageFunctionTable;
    *pcTables = 1;

    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}


extern "C"
BOOL WINAPI DllMain(HINSTANCE /*hinstDLL*/, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        LogMessage("DLL_PROCESS_ATTACH");
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        if (lpvReserved != nullptr)
            break; // do not do cleanup if process termination scenario

        LogMessage("DLL_PROCESS_DETACH");
        break;
    }

    return TRUE;
}
