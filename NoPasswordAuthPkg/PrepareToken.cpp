#include "PrepareToken.hpp"
#include <Lm.h>
#include "Utils.hpp"

#pragma comment(lib, "Netapi32.lib")


static bool NameToSid(const wchar_t* username, PSID* userSid) {
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

static void GetPrimaryGroupSidFromUserSid(PSID userSID, PSID* primaryGroupSID) {
    // duplicate the user sid and replace the last subauthority by DOMAIN_GROUP_RID_USERS
    // cf http://msdn.microsoft.com/en-us/library/aa379649.aspx
    *primaryGroupSID = (PSID)FunctionTable.AllocateLsaHeap(GetLengthSid(userSID));
    CopySid(GetLengthSid(userSID), *primaryGroupSID, userSID);
    UCHAR SubAuthorityCount = *GetSidSubAuthorityCount(*primaryGroupSID);
    // last SubAuthority = RID
    *GetSidSubAuthority(*primaryGroupSID, SubAuthorityCount - 1) = DOMAIN_GROUP_RID_USERS;
}

static bool GetGroups(const wchar_t* UserName, GROUP_USERS_INFO_1** lpGroupInfo, DWORD* pTotalEntries) {
    DWORD NumberOfEntries = 0;
    DWORD status = NetUserGetGroups(NULL, UserName, 1, (LPBYTE*)lpGroupInfo, MAX_PREFERRED_LENGTH, &NumberOfEntries, pTotalEntries);
    if (status != NERR_Success) {
        LogMessage("ERROR: NetUserGetGroups failed with error %u", status );
        return false;
    }
    return true;
}

static bool GetLocalGroups(const wchar_t* UserName, GROUP_USERS_INFO_0** lpGroupInfo, DWORD* pTotalEntries) {
    DWORD NumberOfEntries = 0;
    DWORD status = NetUserGetLocalGroups(NULL, UserName, 0, 0, (LPBYTE*)lpGroupInfo, MAX_PREFERRED_LENGTH, &NumberOfEntries, pTotalEntries);
    if (status != NERR_Success) {
        LogMessage("ERROR: NetUserGetLocalGroups failed with error %u", status);
        return false;
    }
    return true;
}


NTSTATUS UserNameToToken(
    __in LSA_UNICODE_STRING* AccountName,
    __out LSA_TOKEN_INFORMATION_V1** Token,
    __out PNTSTATUS SubStatus
) {
    const LARGE_INTEGER Forever = { 0x7fffffff,0xfffffff };

    // convert username to zero-terminated string
    std::wstring username = ToWstring(*AccountName);
    LogMessage("  UserNameToToken username %ls", username.c_str());

    LogMessage("  Allocating Token...");
    auto* token = (LSA_TOKEN_INFORMATION_V1*)FunctionTable.AllocateLsaHeap(sizeof(LSA_TOKEN_INFORMATION_V1));

    token->ExpirationTime = Forever;

    PSID userSid = nullptr;
    {
        // configure "User"
        if (!NameToSid(username.c_str(), &userSid))
            return STATUS_FAIL_FAST_EXCEPTION;

        token->User.User = {
            .Sid = userSid,
            .Attributes = 0,
        };
    }

    {
        // configure "Groups"
        DWORD NumberOfGroups = 0;
        GROUP_USERS_INFO_1* pGroupInfo = nullptr;
        if (!GetGroups(username.c_str(), &pGroupInfo, &NumberOfGroups)) {
            return STATUS_FAIL_FAST_EXCEPTION;
        }
        LogMessage("  NumberOfGroups: %u", NumberOfGroups);

        DWORD NumberOfLocalGroups = 0;
        GROUP_USERS_INFO_0* pLocalGroupInfo = nullptr;
        if (!GetLocalGroups(username.c_str(), &pLocalGroupInfo, &NumberOfLocalGroups)) {
            return STATUS_FAIL_FAST_EXCEPTION;
        }
        LogMessage("  NumberOfLocalGroups: %u", NumberOfLocalGroups);

        TOKEN_GROUPS* tokenGroups = (TOKEN_GROUPS*)FunctionTable.AllocateLsaHeap(FIELD_OFFSET(TOKEN_GROUPS, Groups[NumberOfGroups + NumberOfLocalGroups]));
        tokenGroups->GroupCount = NumberOfGroups + NumberOfLocalGroups;
        for (size_t i = 0; i < NumberOfGroups; i++) {
            NameToSid(pGroupInfo[i].grui1_name, &tokenGroups->Groups[i].Sid);

            tokenGroups->Groups[i].Attributes = pGroupInfo[i].grui1_attributes;
        }
        for (size_t i = 0; i < NumberOfLocalGroups; i++) {
            NameToSid(pLocalGroupInfo[i].grui0_name, &tokenGroups->Groups[NumberOfGroups + i].Sid);

            // get the attributes of group since pLocalGroupInfo doesn't contain attributes
            if (*GetSidSubAuthority(tokenGroups->Groups[NumberOfGroups + i].Sid, 0) != SECURITY_BUILTIN_DOMAIN_RID)
                tokenGroups->Groups[NumberOfGroups + i].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT;
            else
                tokenGroups->Groups[NumberOfGroups + i].Attributes = 0;
        }

        token->Groups = tokenGroups;
        LogMessage("  token->Groups populated");
    }

    GetPrimaryGroupSidFromUserSid(userSid, &token->PrimaryGroup.PrimaryGroup);

    // TOKEN_PRIVILEGES Privileges not currently configured
    token->Privileges = nullptr;

    // PSID Owner not currently configured
    token->Owner.Owner = (PSID)nullptr;

    // PACL DefaultDacl not currently configured
    token->DefaultDacl.DefaultDacl = nullptr;

    // assign outputs
    *Token = token;
    *SubStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}
