#include "PrepareToken.hpp"
#include <Lm.h>
#include "Utils.hpp"

#pragma comment(lib, "Netapi32.lib")


bool NameToSid(const wchar_t* username, PSID* userSid) {
    DWORD lengthSid = 0;
    SID_NAME_USE Use = {};
    DWORD referencedDomainNameLen = 0;
    BOOL res = LookupAccountNameW(nullptr, username, nullptr, &lengthSid, nullptr, &referencedDomainNameLen, &Use);

    //LogMessage("  Allocating SID with size %u", lengthSid);
    *userSid = (PSID)FunctionTable.AllocateLsaHeap(lengthSid);
    wchar_t* referencedDomainName = (wchar_t*)FunctionTable.AllocateLsaHeap(sizeof(wchar_t) * referencedDomainNameLen);
    res = LookupAccountNameW(nullptr, username, *userSid, &lengthSid, referencedDomainName, &referencedDomainNameLen, &Use);
    if (!res) {
        DWORD err = GetLastError();
        LogMessage("  LookupAccountNameW failed (err %u)", err);
        return false;
    }

    FunctionTable.FreeLsaHeap(referencedDomainName);
    return true;
}

void GetPrimaryGroupSidFromUserSid(PSID userSID, PSID* primaryGroupSID) {
    // duplicate the user sid and replace the last subauthority by DOMAIN_GROUP_RID_USERS
    // cf http://msdn.microsoft.com/en-us/library/aa379649.aspx
    *primaryGroupSID = (PSID)FunctionTable.AllocateLsaHeap(GetLengthSid(userSID));
    CopySid(GetLengthSid(userSID), *primaryGroupSID, userSID);
    UCHAR SubAuthorityCount = *GetSidSubAuthorityCount(*primaryGroupSID);
    // last SubAuthority = RID
    *GetSidSubAuthority(*primaryGroupSID, SubAuthorityCount - 1) = DOMAIN_GROUP_RID_USERS;
}

bool GetGroups(const wchar_t* UserName, GROUP_USERS_INFO_1** lpGroupInfo, DWORD* pTotalEntries) {
    DWORD NumberOfEntries = 0;
    DWORD status = NetUserGetGroups(NULL, UserName, 1, (LPBYTE*)lpGroupInfo, MAX_PREFERRED_LENGTH, &NumberOfEntries, pTotalEntries);
    if (status != NERR_Success) {
        LogMessage("ERROR: NetUserGetGroups failed with error %u", status );
        return false;
    }
    return true;
}

bool GetLocalGroups(const wchar_t* UserName, GROUP_USERS_INFO_0** lpGroupInfo, DWORD* pTotalEntries) {
    DWORD NumberOfEntries = 0;
    DWORD status = NetUserGetLocalGroups(NULL, UserName, 0, 0, (LPBYTE*)lpGroupInfo, MAX_PREFERRED_LENGTH, &NumberOfEntries, pTotalEntries);
    if (status != NERR_Success) {
        LogMessage("ERROR: NetUserGetLocalGroups failed with error %u", status);
        return false;
    }
    return true;
}


NTSTATUS UserNameToToken(__in LSA_UNICODE_STRING* AccountName,
    __out LSA_TOKEN_INFORMATION_V1** Token,
    __out PNTSTATUS SubStatus) {
    const LARGE_INTEGER Forever = { 0x7fffffff,0xfffffff };

    // convert username to zero-terminated string
    std::wstring username = ToWstring(*AccountName);
    LogMessage("  UserNameToToken username %ls", username.c_str());

    LogMessage("  Allocating Token...");
    auto* token = (LSA_TOKEN_INFORMATION_V1*)FunctionTable.AllocateLsaHeap(sizeof(LSA_TOKEN_INFORMATION_V1));

    token->ExpirationTime = Forever;

    PSID userSid = nullptr;
    {
        if (!NameToSid(username.c_str(), &userSid))
            return STATUS_FAIL_FAST_EXCEPTION;

        token->User.User = {
            .Sid = userSid,
            .Attributes = 0,
        };
    }

#if 1
    token->Groups = nullptr;
#else
    token->Groups = (TOKEN_GROUPS*)FunctionTable.AllocateLsaHeap(sizeof(TOKEN_GROUPS));
    *Token->Groups = {
        .GroupCount = 0,
        .Groups = {},
    };
#endif

    GetPrimaryGroupSidFromUserSid(userSid, &token->PrimaryGroup.PrimaryGroup);

#if 1
    token->Privileges = nullptr;
#else
    token->Privileges = (TOKEN_PRIVILEGES*)FunctionTable.AllocateLsaHeap(sizeof(TOKEN_PRIVILEGES));
    *Token->Privileges = {
        .PrivilegeCount = 0,
        .Privileges = {},
    };
#endif

    token->Owner.Owner = (PSID)nullptr;

#if 1
    token->DefaultDacl.DefaultDacl = nullptr;
#else
    token->DefaultDacl.DefaultDacl = (ACL*)FunctionTable.AllocateLsaHeap(sizeof(ACL));
    *token->DefaultDacl.DefaultDacl = ACL{
        .AclRevision = 0,
        .Sbz1 = 0,
        .AclSize = 0,
        .AceCount = 0,
        .Sbz2 = 0,
    };
#endif

    // assign outputs
    * Token = token;
    *SubStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}
