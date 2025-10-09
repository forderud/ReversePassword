#include <Windows.h>
#include <sspi.h>
#include "PrepareProfile.hpp"
#include "Utils.hpp"

static LARGE_INTEGER InfiniteFuture() {
    LARGE_INTEGER val{};
    val.HighPart = 0x7FFFFFFF; // signed
    val.LowPart = 0xFFFFFFFF; // unsigned
    return val;
}

ULONG GetProfileBufferSize(const std::wstring& computername, const MSV1_0_INTERACTIVE_LOGON& logonInfo) {
    return sizeof(MSV1_0_INTERACTIVE_PROFILE) + logonInfo.UserName.Length + (ULONG)(2 * computername.size());
}

std::vector<BYTE> PrepareProfileBuffer(const std::wstring& computername, const MSV1_0_INTERACTIVE_LOGON& logonInfo, BYTE* hostProfileAddress) {
    std::vector<BYTE> profileBuffer(GetProfileBufferSize(computername, logonInfo), (BYTE)0);
    auto* profile = (MSV1_0_INTERACTIVE_PROFILE*)profileBuffer.data();
    size_t offset = sizeof(MSV1_0_INTERACTIVE_PROFILE); // offset to string parameters

    profile->MessageType = MsV1_0InteractiveProfile;
    profile->LogonCount = 42;
    profile->BadPasswordCount = 0;
    profile->LogonTime;
    profile->LogoffTime = InfiniteFuture(); //never
    profile->KickOffTime = InfiniteFuture(); //never
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
            .Buffer = (wchar_t*)(hostProfileAddress + offset),
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
            .Buffer = (wchar_t*)(hostProfileAddress + offset),
        };
        profile->LogonServer = tmp;

        offset += profile->LogonServer.MaximumLength;
    }
    profile->UserFlags = 0;

    return profileBuffer;
}
