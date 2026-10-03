#include "PrepareToken.hpp"
#include "PrepareProfile.hpp"
#include "Utils.hpp"
#include "MagicFile.hpp"
#include "../ReversePasswordEventProvider/EventLogger.hpp"
#include "../ReversePasswordEventProvider/ReversePasswordEventProvider.h"
#include <format>

// exported symbols
#pragma comment(linker, "/export:SpLsaModeInitialize")

LSA_SECPKG_FUNCTION_TABLE FunctionTable;


NTSTATUS NTAPI SpInitialize(_In_ ULONG_PTR PackageId, _In_ SECPKG_PARAMETERS* Parameters, _In_ LSA_SECPKG_FUNCTION_TABLE* functionTable) {
    std::wstring message;
    message += std::format(L"  PackageId: {}\n", PackageId);
    message += std::format(L"  Version: {}\n", Parameters->Version);
    {
        ULONG state = Parameters->MachineState;
        message += L"  MachineState:\n";
        if (state & SECPKG_STATE_ENCRYPTION_PERMITTED) {
            state &= ~SECPKG_STATE_ENCRYPTION_PERMITTED;
            message += L"  - ENCRYPTION_PERMITTED\n";
        }
        if (state & SECPKG_STATE_STRONG_ENCRYPTION_PERMITTED) {
            state &= ~SECPKG_STATE_STRONG_ENCRYPTION_PERMITTED;
            message += L"  - STRONG_ENCRYPTION_PERMITTED\n";
        }
        if (state & SECPKG_STATE_DOMAIN_CONTROLLER) {
            state &= ~SECPKG_STATE_DOMAIN_CONTROLLER;
            message += L"  - DOMAIN_CONTROLLER\n";
        }
        if (state & SECPKG_STATE_WORKSTATION) {
            state &= ~SECPKG_STATE_WORKSTATION;
            message += L"  - WORKSTATION\n";
        }
        if (state & SECPKG_STATE_STANDALONE) {
            state &= ~SECPKG_STATE_STANDALONE;
            message += L"  - STANDALONE\n";
        }
        if (state) {
            // print resudual flags not already covered
            message += std::format(L"  * Unknown flags: 0x{:X}", state);
        }
    }
    message += std::format(L"  SetupMode: {}\n", Parameters->SetupMode);
    // parameters not logged
    Parameters->DomainSid;
    Parameters->DomainName;
    Parameters->DnsDomainName;
    Parameters->DomainGuid;

    FunctionTable = *functionTable; // copy function pointer table

    // NOTICE: Event logging here causes Windows startup problems
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpShutDown() {
    EventLogger log(L"ReversePassword");
    const wchar_t* strings[] = { L"SpShutDown" };
    log.ReportInsertStrings(EVENTLOG_SUCCESS, AUTH_PKG_CATEGORY, MSG_CALL_SUCCESS, strings);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpGetInfo(_Out_ SecPkgInfoW* PackageInfo) {
    // return security package metadata
    PackageInfo->fCapabilities = SECPKG_FLAG_LOGON //  supports LsaLogonUser
                               | SECPKG_FLAG_CLIENT_ONLY; // no server auth support
    PackageInfo->wVersion = SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION;
    PackageInfo->wRPCID = SECPKG_ID_NONE; // no DCE/RPC support
    PackageInfo->cbMaxToken = 0;
    PackageInfo->Name = (wchar_t*)L"NoPasswordAuthPkg";
    PackageInfo->Comment = (wchar_t*)L"Custom authentication package for testing";

    // NOTICE: Event logging here causes Windows startup problems
    return STATUS_SUCCESS;
}


/* Authenticate a user logon attempt.
   Returns STATUS_SUCCESS if the login attempt succeeded. */
NTSTATUS LsaApLogonUser (
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ SECURITY_LOGON_TYPE LogonType,
    _In_reads_bytes_(SubmitBufferSize) VOID* ProtocolSubmitBuffer,
    _In_ VOID* ClientBufferBase,
    _In_ ULONG SubmitBufferSize,
    _Outptr_result_bytebuffer_(*ProfileBufferSize) VOID** ProfileBuffer,
    _Out_ ULONG* ProfileBufferSize,
    _Out_ LUID* LogonId,
    _Out_ NTSTATUS* SubStatus,
    _Out_ LSA_TOKEN_INFORMATION_TYPE* TokenInformationType,
    _Outptr_ VOID** TokenInformation,
    _Out_ LSA_UNICODE_STRING** AccountName,
    _Out_ LSA_UNICODE_STRING** AuthenticatingAuthority
) {
    EventLogger log(L"ReversePassword");

    {
        // clear output arguments first in case of failure
        *ProfileBuffer = nullptr;
        *ProfileBufferSize = 0;
        *LogonId = {};
        *SubStatus = STATUS_SUCCESS; // reason for error
        *TokenInformationType = {};
        *TokenInformation = nullptr;
        *AccountName = nullptr;
        if (AuthenticatingAuthority)
            *AuthenticatingAuthority = nullptr;
    }

    // input arguments
    ClientBufferBase;

    // deliberately restrict supported logontypes to local and remote-desktop
    if ((LogonType != Interactive) && (LogonType != RemoteInteractive)) {
        std::wstring description = std::format(L"STATUS_NOT_IMPLEMENTED, unsupported LogonType {}", (int)LogonType);
        const wchar_t* strings[] = { L"LsaApLogonUser", description.c_str()};
        log.ReportInsertStrings(EVENTLOG_ERROR_TYPE, AUTH_PKG_CATEGORY, MSG_CALL_FAILED, strings);
        return STATUS_NOT_IMPLEMENTED;
    }

    // authentication credentials passed by client
    auto* logonInfo = (MSV1_0_INTERACTIVE_LOGON*)ProtocolSubmitBuffer;
    {
        if (SubmitBufferSize < sizeof(MSV1_0_INTERACTIVE_LOGON)) {
            std::wstring description = std::format(L"STATUS_INVALID_PARAMETER, SubmitBufferSize {} smaller than {}", SubmitBufferSize, sizeof(MSV1_0_INTERACTIVE_LOGON));
            const wchar_t* strings[] = { L"LsaApLogonUser", description.c_str()};
            log.ReportInsertStrings(EVENTLOG_ERROR_TYPE, AUTH_PKG_CATEGORY, MSG_CALL_FAILED, strings);
            return STATUS_INVALID_PARAMETER;
        }

        // make relative pointers absolute to ease later access
        logonInfo->LogonDomainName.Buffer = (wchar_t*)((BYTE*)logonInfo + (size_t)logonInfo->LogonDomainName.Buffer);
        logonInfo->UserName.Buffer = (wchar_t*)((BYTE*)logonInfo + (size_t)logonInfo->UserName.Buffer);
        logonInfo->Password.Buffer = (wchar_t*)((BYTE*)logonInfo + (size_t)logonInfo->Password.Buffer);
    }
    {
        // log user-supplied credentials
        std::wstring description = L"ProtocolSubmitBuffer:";
        description += L"\n  LogonDomainName: " + std::wstring(logonInfo->LogonDomainName.Buffer, logonInfo->LogonDomainName.Length/sizeof(wchar_t));
        description += L"\n  Username: " + std::wstring(logonInfo->UserName.Buffer, logonInfo->UserName.Length/sizeof(wchar_t));
        description += L"\n  Password: ";
        for (size_t i = 0; i < logonInfo->Password.Length/sizeof(wchar_t); ++i)
            description += L"*"; // hide password in logs
        const wchar_t* strings[] = { L"LsaApLogonUser", description.c_str() };
        log.ReportInsertStrings(EVENTLOG_INFORMATION_TYPE, AUTH_PKG_CATEGORY, MSG_CALL_INFO, strings);
    }

    {
        // Authentication check:
        // Check for magic file on removable drive _instead_ of checking username/password.

        std::vector<std::wstring> removable_drives = GetRemovableDrives();
        bool found_magic_file = false;
        for (std::wstring drive : removable_drives) {
            if (DriveHasMagicFile(drive, L"DisablePasswordCheck"))
                found_magic_file = true;
        }

        if (!found_magic_file) {
            *SubStatus = STATUS_WRONG_PASSWORD; // reason for error
            const wchar_t* strings[] = { L"LsaApLogonUser", L"No magic file found on any removable drive"};
            log.ReportInsertStrings(EVENTLOG_ERROR_TYPE, AUTH_PKG_CATEGORY, MSG_CALL_FAILED, strings);
            return STATUS_LOGON_FAILURE;
        }
    }

    // assign output arguments

    {
        wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1]{};
        DWORD computerNameSize = std::size(computerName);
        if (!GetComputerNameW(computerName, &computerNameSize)) {
            std::wstring description = std::format(L"STATUS_INTERNAL_ERROR, GetComputerNameW failed {}", GetLastError());
            const wchar_t* strings[] = { L"LsaApLogonUser", description.c_str()};
            log.ReportInsertStrings(EVENTLOG_ERROR_TYPE, AUTH_PKG_CATEGORY, MSG_CALL_FAILED, strings);
            return STATUS_INTERNAL_ERROR;
        }

        // assign "ProfileBuffer" output argument
        *ProfileBufferSize = GetProfileBufferSize(computerName, *logonInfo);
        FunctionTable.AllocateClientBuffer(ClientRequest, *ProfileBufferSize, ProfileBuffer); // will update *ProfileBuffer

        std::vector<BYTE> profileBuffer = PrepareProfileBuffer(computerName, *logonInfo, (BYTE*)*ProfileBuffer);
        FunctionTable.CopyToClientBuffer(ClientRequest, (ULONG)profileBuffer.size(), *ProfileBuffer, profileBuffer.data()); // copy to caller process
    }

    {
        // assign "LogonId" output argument
        if (!AllocateLocallyUniqueId(LogonId)) {
            return STATUS_FAIL_FAST_EXCEPTION;
        }
        NTSTATUS status = FunctionTable.CreateLogonSession(LogonId);
        if (status != STATUS_SUCCESS) {
            std::wstring description = std::format(L"ERROR: CreateLogonSession failed with err {}", status);
            const wchar_t* strings[] = { L"LsaApLogonUser", description.c_str()};
            log.ReportInsertStrings(EVENTLOG_ERROR_TYPE, AUTH_PKG_CATEGORY, MSG_CALL_FAILED, strings);
            return status;
        }
    }

    {
        // Assign "TokenInformation" output argument
        LSA_TOKEN_INFORMATION_V2* tokenInfo = nullptr;
        NTSTATUS subStatus = 0;
        NTSTATUS status = UserNameToToken(&logonInfo->UserName, &tokenInfo, &subStatus);
        if (status != STATUS_SUCCESS) {
            *SubStatus = subStatus;
            std::wstring description = std::format(L"UserNameToToken failed with err {}", status);
            const wchar_t* strings[] = { L"LsaApLogonUser", description.c_str()};
            log.ReportInsertStrings(EVENTLOG_ERROR_TYPE, AUTH_PKG_CATEGORY, MSG_CALL_FAILED, strings);
            return status;
        }

        *TokenInformationType = LsaTokenInformationV1;
        *TokenInformation = tokenInfo;
    }

    {
        // assign "AccountName" output argument
        *AccountName = CreateLsaUnicodeString(logonInfo->UserName.Buffer, logonInfo->UserName.Length); // mandatory
    }

    if (AuthenticatingAuthority) {
        // assign "AuthenticatingAuthority" output argument
        *AuthenticatingAuthority = (LSA_UNICODE_STRING*)FunctionTable.AllocateLsaHeap(sizeof(LSA_UNICODE_STRING));

        if (logonInfo->LogonDomainName.Length > 0) {
            *AuthenticatingAuthority = CreateLsaUnicodeString(logonInfo->LogonDomainName.Buffer, logonInfo->LogonDomainName.Length);
        } else {
            **AuthenticatingAuthority = {
                .Length = 0,
                .MaximumLength = 0,
                .Buffer = nullptr,
            };
        }
    }

    const wchar_t* strings[] = { L"LsaApLogonUser" };
    log.ReportInsertStrings(EVENTLOG_SUCCESS, AUTH_PKG_CATEGORY, MSG_CALL_SUCCESS, strings);
    return STATUS_SUCCESS;
}

void LsaApLogonTerminated(_In_ LUID* /*LogonId*/) {
    EventLogger log(L"ReversePassword");
    const wchar_t* strings[] = { L"LsaApLogonTerminated" };
    log.ReportInsertStrings(EVENTLOG_SUCCESS, AUTH_PKG_CATEGORY, MSG_CALL_SUCCESS, strings);
}

SECPKG_FUNCTION_TABLE SecurityPackageFunctionTable = {
    .InitializePackage = nullptr,
    .LogonUser = LsaApLogonUser,
    .CallPackage = nullptr,
    .LogonTerminated = LsaApLogonTerminated,
    .CallPackageUntrusted = nullptr,
    .CallPackagePassthrough = nullptr,
    .LogonUserEx = nullptr,
    .LogonUserEx2 = nullptr,
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

/** LSA calls SpLsaModeInitialize() when loading SSP/AP DLLs. */
extern "C"
NTSTATUS NTAPI SpLsaModeInitialize(
    _In_ ULONG /*LsaVersion*/,
    _Out_ ULONG* PackageVersion,
    _Out_ SECPKG_FUNCTION_TABLE** ppTables,
    _Out_ ULONG* pcTables
) {
    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables = &SecurityPackageFunctionTable;
    *pcTables = 1;
    return STATUS_SUCCESS;
}
