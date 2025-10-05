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

void LogMessage(const char* message, ...) {
#ifdef NDEBUG
    message;
#else
    // append to log file
    FILE* file = nullptr;
    fopen_s(&file, "C:\\CustomAuthPkg_log.txt", "a+");
    {
        // print variadic message
        va_list args;
        va_start(args, message);
        _vfprintf_l(file, message, NULL, args);
        va_end(args);
    }
    fprintf(file, "\n");
    fclose(file);
#endif
}

/** Allocate and create a new LSA_STRING object. */
LSA_STRING* CreateLsaString(const std::string& msg) {
    auto msg_len = (USHORT)msg.size(); // exclude null-termination

    assert(DispatchTable.AllocateLsaHeap);
    auto* obj = (LSA_STRING*)DispatchTable.AllocateLsaHeap(sizeof(LSA_STRING));
    obj->Buffer = (char*)DispatchTable.AllocateLsaHeap(msg_len);
    strcpy_s(obj->Buffer, msg_len, msg.c_str());
    obj->Length = msg_len;
    obj->MaximumLength = msg_len;
    return obj;
}

/** Allocate and create a new LSA_STRING object. */
LSA_UNICODE_STRING* CreateLsaString(const std::wstring& msg) {
    auto msg_len = (USHORT)msg.size(); // exclude null-termination

    assert(DispatchTable.AllocateLsaHeap);
    auto* obj = (LSA_UNICODE_STRING*)DispatchTable.AllocateLsaHeap(sizeof(LSA_UNICODE_STRING));
    obj->Buffer = (wchar_t*)DispatchTable.AllocateLsaHeap(2*msg_len);
    wcsncpy_s(obj->Buffer, msg_len, msg.c_str(), msg_len);
    obj->Length = 2*msg_len;
    obj->MaximumLength = 2*msg_len;
    return obj;
}

// LSA calls LsaApInitializePackage() when loading AuthPkg DLL
NTSTATUS LsaApInitializePackage(ULONG AuthenticationPackageId,
    LSA_DISPATCH_TABLE* LsaDispatchTable,
    LSA_STRING* Database,
    LSA_STRING* Confidentiality,
    LSA_STRING** AuthenticationPackageName
) {
    LogMessage("LsaApInitializePackage");

    assert(!Database);
    assert(!Confidentiality);
    
    DispatchTable = *LsaDispatchTable; // copy function pointer table
    *AuthenticationPackageName = CreateLsaString("CustomAuthPkg"); // freed by caller

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpInitialize(ULONG_PTR PackageId, SECPKG_PARAMETERS* Parameters, LSA_SECPKG_FUNCTION_TABLE* FunctionTable) {
    LogMessage("SpInitialize");

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpShutDown() {
    LogMessage("SpShutDown");

    return STATUS_SUCCESS;
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
    PUNICODE_STRING* AccountName,
    PUNICODE_STRING* AuthenticatingAuthority,
    PUNICODE_STRING* MachineName,
    SECPKG_PRIMARY_CRED* PrimaryCredentials,
    SECPKG_SUPPLEMENTAL_CRED_ARRAY** SupplementalCredentials)
{
    // input arguments
    ClientRequest;
    LogMessage("  LogonType: %i", LogonType); // Interactive=2
    ProtocolSubmitBuffer;
    ClientBufferBase;
    LogMessage("  ProtocolSubmitBuffer size: %i", SubmitBufferSize);

    // assign output arguments
    *ProfileBuffer = nullptr;
    *ProfileBufferSize = 0;
    *LogonId = { 0, 0 };
    *SubStatus = STATUS_SUCCESS; // reason for error
    *TokenInformationType = LsaTokenInformationNull;
    *TokenInformation = nullptr;
    *AccountName = CreateLsaString(L"SomeUser"); // mandatory
    *AuthenticatingAuthority = nullptr; // optional
    *MachineName = nullptr; // optional
    *PrimaryCredentials = {};
    *SupplementalCredentials = nullptr;

    return STATUS_SUCCESS;
}

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

NTSTATUS LsaApCallPackage(PLSA_CLIENT_REQUEST ClientRequest,
    VOID* ProtocolSubmitBuffer,
    VOID* ClientBufferBase,
    ULONG SubmitBufferLength,
    VOID** ProtocolReturnBuffer,
    ULONG* ReturnBufferLength,
    NTSTATUS* ProtocolStatus)
{
    LogMessage("LsaApCallPackage");

    return STATUS_SUCCESS;
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

    return STATUS_SUCCESS;
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

    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables = &SecurityPackageFunctionTable;
    *pcTables = 1;

    return STATUS_SUCCESS;
}
