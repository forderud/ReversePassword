#include <Windows.h>
#include <sspi.h>
#include "PrepareProfile.hpp"
#include "Utils.hpp"


std::vector<BYTE> PrepareProfileBuffer(const std::wstring& computername, const MSV1_0_INTERACTIVE_LOGON& logonInfo, PLSA_CLIENT_REQUEST ClientRequest, VOID** ProfileBuffer) {
    ULONG profileSize = sizeof(MSV1_0_INTERACTIVE_PROFILE) + logonInfo.UserName.Length + (ULONG)(2 * computername.size());

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
        memcpy(/*dst*/profileBuffer.data() + offset, /*src*/logonInfo.UserName.Buffer, logonInfo.UserName.MaximumLength);

        LSA_UNICODE_STRING tmp = {
            .Length = logonInfo.UserName.Length,
            .MaximumLength = logonInfo.UserName.MaximumLength,
            .Buffer = (wchar_t*)((BYTE*)*ProfileBuffer + offset),
        };
        profile->FullName = tmp;

        offset += profile->FullName.MaximumLength;
    }
    profile->ProfilePath; // observed to be empty
    profile->HomeDirectoryDrive; // observed to be empty
    {
        // set "LogonServer"
        memcpy(/*dst*/profileBuffer.data() + offset, /*src*/computername.data(), computername.size());

        LSA_UNICODE_STRING tmp = {
            .Length = (USHORT)(2 * computername.size()),
            .MaximumLength = (USHORT)(2 * computername.size()),
            .Buffer = (wchar_t*)((BYTE*)*ProfileBuffer + offset),
        };
        profile->LogonServer = tmp;

        offset += profile->LogonServer.MaximumLength;
    }
    profile->UserFlags = 0;

    return profileBuffer;
}
