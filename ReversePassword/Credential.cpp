#include "Credential.Hpp"
#include <sddl.h>
#include <ntsecapi.h>
#include <lm.h>
#include <wincred.h>
#include <comdef.h> // for _com_error


namespace {
    HRESULT GetAccountName(const WCHAR* sidText, std::wstring& accountName) {
        PSID sid = nullptr;
        if (!ConvertStringSidToSidW(sidText, &sid))
            return HRESULT_FROM_WIN32(GetLastError());

        DWORD nameLength = 0;
        DWORD domainLength = 0;
        SID_NAME_USE use{};
        LookupAccountSidW(nullptr, sid, nullptr, &nameLength, nullptr, &domainLength, &use);
        const DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) {
            LocalFree(sid);
            return HRESULT_FROM_WIN32(error);
        }

        std::wstring name(nameLength, L'\0');
        std::wstring domain(domainLength, L'\0');
        const BOOL found = LookupAccountSidW(nullptr, sid, name.data(), &nameLength,
            domain.data(), &domainLength, &use);
        LocalFree(sid);
        if (!found)
            return HRESULT_FROM_WIN32(GetLastError());

        name.resize(nameLength);
        domain.resize(domainLength);
        accountName = domain.empty() ? name : domain + L"\\" + name;
        return S_OK;
    }

    HRESULT GetAuthenticationPackage(ULONG* package) {
        if (!package)
            return E_POINTER;

        HANDLE lsa = nullptr;
        NTSTATUS status = LsaConnectUntrusted(&lsa);
        if (status != STATUS_SUCCESS)
            return HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));

        const auto lookup = [lsa, package](const char* name)
            {
                LSA_STRING packageName{};
                packageName.Buffer = const_cast<char*>(name);
                packageName.Length = static_cast<USHORT>(strlen(name));
                packageName.MaximumLength = packageName.Length;
                return LsaLookupAuthenticationPackage(lsa, &packageName, package);
            };

        status = lookup("NoPasswordAuthPkg"); // use NoPasswordAuthPkg if installed
        if (status != STATUS_SUCCESS)
            status = lookup("Negotiate"); // falback to Negotiate
        LsaDeregisterLogonProcess(lsa);
        return status == STATUS_SUCCESS ? S_OK : HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));
    }

    HRESULT CredPackAuthenticationBufferWrap(const WCHAR* userName, const WCHAR* password, /*out*/BYTE** buffer, /*out*/DWORD* size) {
        if (!buffer || !size)
            return E_POINTER;

        *buffer = nullptr;
        *size = 0;

        DWORD required = 0;
        CredPackAuthenticationBufferW(0, const_cast<WCHAR*>(userName), const_cast<WCHAR*>(password), nullptr, &required);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return HRESULT_FROM_WIN32(GetLastError());

        BYTE* packed = static_cast<BYTE*>(CoTaskMemAlloc(required));
        if (!CredPackAuthenticationBufferW(0, const_cast<WCHAR*>(userName), const_cast<WCHAR*>(password), packed, &required)) {
            const HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
            CoTaskMemFree(packed);
            return hr;
        }
        *buffer = packed;
        *size = required;
        return S_OK;
    }

    std::wstring Reverse(std::wstring value) {
        std::reverse(value.begin(), value.end());
        return value;
    }
}


HRESULT Credential::SetSelected(BOOL* autoLogon) {
    if (!autoLogon)
        return E_POINTER;

    *autoLogon = FALSE;
    return S_OK;
}

HRESULT Credential::SetDeselected() {
    if (Field* password = GetField(PASSWORD_FIELD))
        password->value = {};

    if (Field* password = GetField(NEW_PASSWORD_FIELD))
        password->value = {};

    return S_OK;
}

HRESULT Credential::GetFieldState(DWORD fieldId, CREDENTIAL_PROVIDER_FIELD_STATE* state,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactiveState) {
    Field* field = GetField(fieldId);
    if (!field || !state || !interactiveState)
        return E_INVALIDARG;

    *state = field->state;
    *interactiveState = CPFIS_NONE;
    return S_OK;
}

HRESULT Credential::GetStringValue(DWORD fieldId, WCHAR** value) {
    Field* field = GetField(fieldId);
    if (!field || !value)
        return E_INVALIDARG;

    if (field->descriptor.cpft < CPFT_LARGE_TEXT || field->descriptor.cpft > CPFT_PASSWORD_TEXT)
        return E_INVALIDARG;

    *value = DuplicateString(std::get<std::wstring>(field->value).c_str());
    return *value ? S_OK : E_POINTER;
}

HRESULT Credential::GetBitmapValue(DWORD fieldId, HBITMAP* bitmap) {
    if (fieldId != ICON_FIELD || !bitmap)
        return E_INVALIDARG;

    *bitmap = static_cast<HBITMAP>(LoadImageW(_AtlBaseModule.GetModuleInstance(), MAKEINTRESOURCEW(IDB_TILE_ICON),
        IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION));
    return *bitmap ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

HRESULT Credential::GetSubmitButtonValue(DWORD fieldId, DWORD* adjacentTo) {
    if (fieldId != SUBMIT_BUTTON_FIELD || !adjacentTo)
        return E_INVALIDARG;

    Field* field = GetField(fieldId);
    if (!field)
        return E_INVALIDARG;

    *adjacentTo = std::get<DWORD>(field->value);
    return S_OK;
}

HRESULT Credential::SetStringValue(DWORD fieldId, const WCHAR* value) {
    Field* field = GetField(fieldId);
    if (!field || !value)
        return E_INVALIDARG;

    if (field->descriptor.cpft != CPFT_EDIT_TEXT && field->descriptor.cpft != CPFT_PASSWORD_TEXT)
        return E_INVALIDARG;

    field->value = value;
    return S_OK;
}

HRESULT Credential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
    WCHAR** statusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) {
    if (!response || !serialization || !statusText || !statusIcon)
        return E_POINTER;

    *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *serialization = {};
    *statusText = nullptr;
    *statusIcon = CPSI_NONE;

    if (m_view->usage == CPUS_CHANGE_PASSWORD) {
        // pasword change logic
        std::wstring accountName;
        HRESULT hr = GetAccountName(m_sid.c_str(), accountName);
        if (FAILED(hr))
            return hr;

        const size_t separator = accountName.find(L'\\');
        if (separator == std::wstring::npos)
            return E_FAIL;

        const std::wstring oldPassword = Reverse(std::get<std::wstring>(GetField(PASSWORD_FIELD)->value));
        const std::wstring newPassword = Reverse(std::get<std::wstring>(GetField(NEW_PASSWORD_FIELD)->value));
        const NET_API_STATUS resultCode = NetUserChangePassword(accountName.substr(0, separator).c_str(),
            accountName.substr(separator + 1).c_str(),
            oldPassword.c_str(), newPassword.c_str());
        if (resultCode == NERR_Success)
        {
            *statusIcon = CPSI_SUCCESS;
            *statusText = DuplicateString(L"Password changed.");
        }
        else
        {
            *statusIcon = CPSI_ERROR;
            const std::wstring message = L"Password change failed with error: " + std::to_wstring(resultCode);
            *statusText = DuplicateString(message.c_str());
        }
        *response = CPGSR_NO_CREDENTIAL_FINISHED;
        const wchar_t* strings[] = { L"GetSerialization" };
        m_log.ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_SUCCESS, strings);
        return S_OK;
    }

    // CPUS_LOGON, CPUS_UNLOCK_WORKSTATION or CPUS_CREDUI logic
    ULONG authenticationPackage = 0;
    HRESULT hr = GetAuthenticationPackage(&authenticationPackage);
    if (FAILED(hr))
        return hr;

    std::wstring userName;
    if (m_view->usage == CPUS_CREDUI) {
        userName = std::get<std::wstring>(GetField(USER_NAME_FIELD)->value); // user entered

        const size_t separator = userName.find(L'\\');
        if (separator == std::wstring::npos) {
            // prepend domain name
            wchar_t domain[MAX_COMPUTERNAME_LENGTH + 1]{};
            DWORD size = std::size(domain);
            if (GetComputerNameW(domain, &size)) {
                userName = domain + std::wstring(L"\\") + userName;
            }
        }
    }
    else {
        hr = GetAccountName(m_sid.c_str(), userName); // implicit
        if (FAILED(hr))
            return hr;
    }

    const std::wstring password = Reverse(std::get<std::wstring>(GetField(PASSWORD_FIELD)->value));
    hr = CredPackAuthenticationBufferWrap(userName.c_str(), password.c_str(), &serialization->rgbSerialization,
        &serialization->cbSerialization);
    if (FAILED(hr)) {
        *statusIcon = CPSI_ERROR;
        *statusText = DuplicateString(L"Failed to pack credentials.");
        const wchar_t* strings[] = { L"GetSerialization", L"Failed to pack credentials." };
        m_log.ReportInsertStrings(EVENTLOG_ERROR_TYPE, CRED_PROVIDER_CATEGORY, MSG_CALL_FAILED, strings);
        return hr;
    }

    serialization->ulAuthenticationPackage = authenticationPackage;
    serialization->clsidCredentialProvider = CLSID_ReversePassword;
    // cbSerialization & rgbSerialization fields already assigned above
    *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
    *statusIcon = CPSI_SUCCESS;
    const wchar_t* strings[] = { L"GetSerialization" };
    m_log.ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_SUCCESS, strings);
    return S_OK;
}

HRESULT Credential::ReportResult(NTSTATUS status, NTSTATUS substatus, WCHAR** statusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) {
    if (!statusText || !statusIcon)
        return E_POINTER;

    *statusText = nullptr;
    *statusIcon = CPSI_NONE;

    if (status != STATUS_SUCCESS) {
        std::wstring message = L"Logon failed with status: ";
        message += _com_error(status).ErrorMessage();
        message += L", substatus: ";
        message += _com_error(substatus).ErrorMessage();
        *statusText = DuplicateString(message.c_str());

        const wchar_t* strings[] = { L"ReportResult", message.c_str() };
        m_log.ReportInsertStrings(EVENTLOG_ERROR_TYPE, CRED_PROVIDER_CATEGORY, MSG_CALL_FAILED, strings);
    } else {
        const wchar_t* strings[] = { L"ReportResult" };
        m_log.ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_SUCCESS, strings);
    }
    return S_OK;
}

HRESULT Credential::GetUserSid(WCHAR** sid) {
    if (!sid)
        return E_POINTER;

    *sid = DuplicateString(m_sid.c_str());
    return S_OK;
}
