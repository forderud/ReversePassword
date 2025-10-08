#include "PrepareToken.hpp"
#include <vector>

// exported symbols
// "DllMain" implicitly exported
#pragma comment(linker, "/export:SpLsaModeInitialize")

LSA_SECPKG_FUNCTION_TABLE FunctionTable;

#include "Utils.hpp"


NTSTATUS NTAPI SpInitialize(ULONG_PTR PackageId, SECPKG_PARAMETERS* Parameters, LSA_SECPKG_FUNCTION_TABLE* functionTable) {
    LogMessage("SpInitialize");
    PackageId;
    Parameters;
    FunctionTable = *functionTable; // copy function pointer table

    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpShutDown() {
    LogMessage("SpShutDown");
    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpGetInfo(SecPkgInfoW* PackageInfo) {
    LogMessage("SpGetInfo");

    // return security package metadata
    PackageInfo->fCapabilities = SECPKG_FLAG_ACCEPT_WIN32_NAME | SECPKG_FLAG_CONNECTION;
    PackageInfo->wVersion = 1;
    PackageInfo->wRPCID = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = 0;
    PackageInfo->Name = (wchar_t*)L"NoPasswordAuthPkg";
    PackageInfo->Comment = (wchar_t*)L"Custom authentication package for testing";

    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

NTSTATUS LsaApLogonUserEx2 (
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
    LogMessage("LsaApLogonUserEx2");

    // input arguments
    ClientRequest;
    LogMessage("  LogonType: %i", LogonType); // Interactive=2
    //LogMessage("  ProtocolSubmitBuffer: 0x%p", ProtocolSubmitBuffer);
    ClientBufferBase;
    //LogMessage("  ClientBufferBase: 0x%p", ClientBufferBase);
    LogMessage("  ProtocolSubmitBuffer size: %i", SubmitBufferSize);

    if (LogonType != Interactive) {
        LogMessage("  return STATUS_NOT_IMPLEMENTED (unsupported LogonType)");
        return STATUS_NOT_IMPLEMENTED;
    }

    auto* logonInfo = (MSV1_0_INTERACTIVE_LOGON*)ProtocolSubmitBuffer;
    {
        if (SubmitBufferSize < sizeof(MSV1_0_INTERACTIVE_LOGON)) {
            LogMessage("  ERROR: SubmitBufferSize too small");
            return STATUS_INVALID_PARAMETER;
        }

        // make relative pointers absolute to ease later access
        logonInfo->LogonDomainName.Buffer = (wchar_t*)((BYTE*)logonInfo + (size_t)logonInfo->LogonDomainName.Buffer);
        logonInfo->UserName.Buffer = (wchar_t*)((BYTE*)logonInfo + (size_t)logonInfo->UserName.Buffer);
        logonInfo->Password.Buffer = (wchar_t*)((BYTE*)logonInfo + (size_t)logonInfo->Password.Buffer);
    }

    wchar_t computerNameBuf[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD computerNameSize = ARRAYSIZE(computerNameBuf);
    if (!GetComputerNameW(computerNameBuf, &computerNameSize)) {
        LogMessage("  return STATUS_INTERNAL_ERROR (GetComputerNameW failed)");
        return STATUS_INTERNAL_ERROR;
    }

    // assign output arguments

    {
        // assign "ProfileBuffer" output argument
        std::wstring computerName(computerNameBuf);

        ULONG profileSize = sizeof(MSV1_0_INTERACTIVE_PROFILE) + logonInfo->UserName.Length + (ULONG)(2*computerName.size());
        FunctionTable.AllocateClientBuffer(ClientRequest, (ULONG)profileSize, ProfileBuffer);
        std::vector<BYTE> profileBuffer(profileSize, (BYTE)0);
        auto* profile = (MSV1_0_INTERACTIVE_PROFILE*)profileBuffer.data();
        size_t offset = sizeof(MSV1_0_INTERACTIVE_PROFILE); // offset to string parameters

        profile->MessageType = MsV1_0InteractiveProfile;
        profile->LogonCount = 42;
        profile->BadPasswordCount = 0;
        profile->LogonTime;
        profile->LogoffTime = { 0xffffffff, 0x7fffffff };
        profile->KickOffTime = { 0xffffffff, 0x7fffffff };
        profile->PasswordLastSet;
        profile->PasswordCanChange;
        profile->PasswordMustChange;
        profile->LogonScript; // observed to be empty
        profile->HomeDirectory; // observed to be empty
        {
            // set "UserName"
            memcpy(/*dst*/profileBuffer.data() + offset, /*src*/logonInfo->UserName.Buffer, logonInfo->UserName.MaximumLength);

            LSA_UNICODE_STRING tmp = {
                .Length = logonInfo->UserName.Length,
                .MaximumLength = logonInfo->UserName.MaximumLength,
                .Buffer = (wchar_t*)((BYTE*)*ProfileBuffer + offset),
            };
            profile->FullName = tmp;

            offset += profile->FullName.MaximumLength;
        }
        profile->ProfilePath; // observed to be empty
        profile->HomeDirectoryDrive; // observed to be empty
        {
            // set "LogonServer"
            memcpy(/*dst*/profileBuffer.data() + offset, /*src*/computerName.data(), computerName.size());

            LSA_UNICODE_STRING tmp = {
                .Length = (USHORT)(2*computerName.size()),
                .MaximumLength = (USHORT)(2*computerName.size()),
                .Buffer = (wchar_t*)((BYTE*)*ProfileBuffer + offset),
            };
            profile->LogonServer = tmp;

            offset += profile->LogonServer.MaximumLength;
        }
        profile->UserFlags = 0;

        // copy profile buffer to caller
        FunctionTable.CopyToClientBuffer(ClientRequest, (ULONG)profileBuffer.size(), *ProfileBuffer, profileBuffer.data());
        *ProfileBufferSize = (ULONG)profileBuffer.size();
    }

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

    {
        // Assign "TokenInformation" output argument
        LSA_TOKEN_INFORMATION_V2* MyTokenInformation = nullptr;
        NTSTATUS subStatus = 0;
        NTSTATUS status = UserNameToToken(&logonInfo->UserName, &MyTokenInformation, &subStatus);
        if (status != STATUS_SUCCESS) {
            LogMessage("ERROR: UserNameToToken failed with err: 0x%x", status);
            *SubStatus = subStatus;
            return status;
        }

        *TokenInformationType = LsaTokenInformationV1;
        *TokenInformation = MyTokenInformation;
    }

    {
        // assign "AccountName" output argument
        if (SubmitBufferSize < sizeof(MSV1_0_INTERACTIVE_LOGON)) {
            LogMessage("  ERROR: SubmitBufferSize too small");
            return STATUS_INVALID_PARAMETER;
        }

        LogMessage("  AccountName: %ls", ToWstring(logonInfo->UserName).c_str());
        *AccountName = CreateLsaUnicodeString(logonInfo->UserName.Buffer, logonInfo->UserName.Length); // mandatory
    }

    if (AuthenticatingAuthority) {
        // assign "AuthenticatingAuthority" output argument
        *AuthenticatingAuthority = (LSA_UNICODE_STRING*)FunctionTable.AllocateLsaHeap(sizeof(LSA_UNICODE_STRING));

        if (logonInfo->LogonDomainName.Length > 0) {
            LogMessage("  AuthenticatingAuthority: %ls", ToWstring(logonInfo->LogonDomainName).c_str());
            *AuthenticatingAuthority = CreateLsaUnicodeString(logonInfo->LogonDomainName.Buffer, logonInfo->LogonDomainName.Length);
        } else {
            LogMessage("  AuthenticatingAuthority: <empty>");
            **AuthenticatingAuthority = {
                .Length = 0,
                .MaximumLength = 0,
                .Buffer = nullptr,
            };
        }
    }

    if (MachineName) {
        // assign "MachineName" output argument
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

void LsaApLogonTerminated(LUID* LogonId) {
    LogMessage("LsaApLogonTerminated");
    LogonId;
    LogMessage("  return");
}

SECPKG_FUNCTION_TABLE SecurityPackageFunctionTable = {
    .InitializePackage = nullptr,
    .LogonUser = nullptr,
    .CallPackage = nullptr,

    .LogonTerminated = LsaApLogonTerminated,
    .CallPackageUntrusted = nullptr,
    .CallPackagePassthrough = nullptr,
    .LogonUserEx = nullptr,
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
