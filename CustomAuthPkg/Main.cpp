#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#define SECURITY_WIN32 // required by sspi.h
#include <sspi.h>
#include <NTSecAPI.h>  // for LSA_STRING
#include <ntsecpkg.h>  // for LSA_DISPATCH_TABLE
#include <cassert>
#include <fstream>

// exported symbols
#pragma comment(linker, "/export:SpLsaModeInitialize" )

#pragma warning(disable: 4100) // unreferenced formal parameter


LSA_DISPATCH_TABLE DispatchTable;
LSA_STRING         PackageName;

void LogMessage(const char* message) {
#ifdef NDEBUG
    message;
#else
    // append to log
    std::ofstream logFile("C:\\CustomAuthPkg_log.txt", std::ios_base::app);
    logFile << message;
    logFile << "\n";
#endif
}

LSA_STRING CreateLsaString(const char msg[]) {
    USHORT msg_len = sizeof(msg) - 1; // exclude null-termination

    LSA_STRING str{};
    str.Buffer = (char*)DispatchTable.AllocateLsaHeap(msg_len);
    strcpy_s(str.Buffer, msg_len, msg);
    str.Length = msg_len;
    str.MaximumLength = msg_len;
    return str;
}

// LSA calls LsaApInitializePackage() when loading AuthPkg DLL
NTSTATUS LsaApInitializePackage(ULONG AuthenticationPackageId,
    PLSA_DISPATCH_TABLE LsaDispatchTable,
    PLSA_STRING Database,
    PLSA_STRING Confidentiality,
    PLSA_STRING* AuthenticationPackageName
) {
    LogMessage("LsaApInitializePackage");

    DispatchTable = *LsaDispatchTable; // copy function pointer table

    PackageName = CreateLsaString("CustomAuthPkg");
    (*AuthenticationPackageName) = &PackageName;

    return 0;
}

NTSTATUS NTAPI SpInitialize(ULONG_PTR PackageId, SECPKG_PARAMETERS* Parameters, LSA_SECPKG_FUNCTION_TABLE* FunctionTable) {
    LogMessage("SpInitialize");
    return 0;
}

NTSTATUS NTAPI SpShutDown() {
    LogMessage("SpShutDown");
    return 0;
}

NTSTATUS NTAPI SpGetInfo(SecPkgInfoW* PackageInfo) {
    LogMessage("SpGetInfo");

    // return security package metadata
    PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
    PackageInfo->wVersion = 1;
    PackageInfo->wRPCID = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = 0;
    PackageInfo->Name = (SEC_WCHAR*)L"CustomAuthPkg";
    PackageInfo->Comment = (SEC_WCHAR*)L"Custom security package for testing";

    return 0;
}

NTSTATUS LsaApLogonUser(PLSA_CLIENT_REQUEST ClientRequest,
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
    return 0;
}

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
    return 0;
}

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
    return 0;
}

NTSTATUS LsaApCallPackage(PLSA_CLIENT_REQUEST ClientRequest,
    VOID* ProtocolSubmitBuffer,
    VOID* ClientBufferBase,
    ULONG SubmitBufferLength,
    VOID** ProtocolReturnBuffer,
    ULONG* ReturnBufferLength,
    NTSTATUS* ProtocolStatus)
{
    LogMessage("LsaApCallPackage");
    return 0;
}

void LsaApLogonTerminated(LUID* LogonId) {
    LogMessage("LsaApLogonTerminated");
}

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
    return 0;
}

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
    return 0;
}


SECPKG_FUNCTION_TABLE SecurityPackageFunctionTable = {
    LsaApInitializePackage,
    LsaApLogonUser,
    LsaApCallPackage,
    LsaApLogonTerminated,
    LsaApCallPackageUntrusted,
    LsaApCallPackagePassthrough,
    LsaApLogonUserEx,
    LsaApLogonUserEx2,
    SpInitialize,
    SpShutDown,
    SpGetInfo,
    NULL, // SpAcceptCredentialsFn
    NULL, // SpAcquireCredentialsHandleFn
    NULL, // SpQueryCredentialsAttributesFn
    NULL, // SpFreeCredentialsHandleFn
    NULL, // SpSaveCredentialsFn
    NULL, // SpGetCredentialsFn
    NULL, // SpDeleteCredentialsFn
    NULL, // SpInitLsaModeContextFn
    NULL, // SpAcceptLsaModeContextFn
    NULL, // SpDeleteContextFn
    NULL, // SpApplyControlTokenFn
    NULL, // SpGetUserInfoFn
    NULL, // SpGetExtendedInformationFn
    NULL, // SpQueryContextAttributesFn
    NULL, // SpAddCredentialsFn
    NULL, // SpSetExtendedInformationFn
    NULL, // SpSetContextAttributesFn
    NULL, // SpSetCredentialsAttributesFn
    NULL, // SpChangeAccountPasswordFn
    NULL, // SpQueryMetaDataFn
    NULL, // SpExchangeMetaDataFn
    NULL, // SpGetCredUIContextFn
    NULL, // SpUpdateCredentialsFn
    NULL, // SpValidateTargetInfoFn
    NULL, // LSA_AP_POST_LOGON_USER
    NULL, // SpGetRemoteCredGuardLogonBufferFn
    NULL, // SpGetRemoteCredGuardSupplementalCredsFn
    NULL, // SpGetTbalSupplementalCredsFn
    NULL, // PLSA_AP_LOGON_USER_EX3
    NULL, // PLSA_AP_PRE_LOGON_USER_SURROGATE
    NULL, // PLSA_AP_POST_LOGON_USER_SURROGATE
    NULL, // SpExtractTargetInfoFn
};

// LSA calls SpLsaModeInitialize() when loading SSP DLL
extern "C"
NTSTATUS NTAPI SpLsaModeInitialize(ULONG LsaVersion, ULONG* PackageVersion, SECPKG_FUNCTION_TABLE** ppTables, ULONG* pcTables) {
    LogMessage("SpLsaModeInitialize");

    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables = &SecurityPackageFunctionTable;
    *pcTables = 1;

    return STATUS_SUCCESS;
}
