#include "CredentialProvider.hpp"
#include "Credential.hpp"
#include <ntsecapi.h>
#include "../NoPasswordAuthPkg/MagicFile.hpp"
#include "../ReversePasswordEventProv/ReversePasswordEventProv.h"


namespace {
    bool IsSupportedScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO usage, bool showPassword) {
        switch (usage) {
        case CPUS_LOGON:
        case CPUS_UNLOCK_WORKSTATION:
            return true;

        case CPUS_CHANGE_PASSWORD:
            return showPassword; // disable when using NoPasswordAuthPkg 

        case CPUS_CREDUI:
            return true;

        case CPUS_INVALID:
        case CPUS_PLAP:
        default:
            return false;
        }
    }

    HRESULT GetAuthenticationPackage(ULONG* package) {
        if (!package)
            return E_POINTER;

        HANDLE lsa = nullptr;
        NTSTATUS status = LsaConnectUntrusted(&lsa);
        if (status != STATUS_SUCCESS)
            return HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));

        const auto lookup = [lsa](const char* name, /*out*/ULONG* package)
            {
                LSA_STRING packageName{};
                packageName.Buffer = const_cast<char*>(name);
                packageName.Length = static_cast<USHORT>(strlen(name));
                packageName.MaximumLength = packageName.Length;
                return LsaLookupAuthenticationPackage(lsa, &packageName, package);
            };

        status = lookup("NoPasswordAuthPkg", /*out*/package); // use NoPasswordAuthPkg if installed
        LsaDeregisterLogonProcess(lsa);
        return status == STATUS_SUCCESS ? S_OK : HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));
    }
}


std::shared_ptr<CredentialView> CreateView(CREDENTIAL_PROVIDER_USAGE_SCENARIO usage, bool showPassword) {
    if (!IsSupportedScenario(usage, showPassword))
        return {};

    auto view = std::make_shared<CredentialView>();
    view->usage = usage;

    const auto addField = [&view](CREDENTIAL_PROVIDER_FIELD_TYPE type, const WCHAR* label,
        CREDENTIAL_PROVIDER_FIELD_STATE state, std::variant<std::wstring, DWORD> value)
        {
            Field field{};
            field.descriptor.dwFieldID = static_cast<DWORD>(view->fields.size());
            field.descriptor.cpft = type;
            field.descriptor.pszLabel = const_cast<WCHAR*>(label);
            field.state = state;
            field.value = value;
            view->fields.push_back(std::move(field));
        };

    addField(CPFT_TILE_IMAGE, L"Icon", CPFS_DISPLAY_IN_BOTH, {}); // ICON_FIELD

    addField(CPFT_LARGE_TEXT, nullptr, CPFS_DISPLAY_IN_BOTH, showPassword ? L"Reverse Password" : L"No Password");
    DWORD adjacentField = 1;

    const auto usernameState = (usage == CPUS_CREDUI) ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
    addField(CPFT_EDIT_TEXT, L"Username", usernameState, {}); // USERNAME_FIELD
    if (usernameState != CPFS_HIDDEN)
        adjacentField = USERNAME_FIELD;

    const auto passwordState = showPassword ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
    addField(CPFT_PASSWORD_TEXT, L"Password", passwordState, {}); // PASSWORD_FIELD
    if (passwordState != CPFS_HIDDEN)
        adjacentField = PASSWORD_FIELD;

    const auto newPasswordState = (usage == CPUS_CHANGE_PASSWORD) ? CPFS_DISPLAY_IN_BOTH : CPFS_HIDDEN;
    addField(CPFT_PASSWORD_TEXT, L"New password", newPasswordState, {}); // NEW_PASSWORD_FIELD
    if (newPasswordState != CPFS_HIDDEN)
        adjacentField = NEW_PASSWORD_FIELD;

    addField(CPFT_SUBMIT_BUTTON, L"Submit", CPFS_DISPLAY_IN_SELECTED_TILE, adjacentField); // SUBMIT_BUTTON_FIELD
    return view;
}

HRESULT CredentialProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO usage, DWORD /*flags*/) {
#ifdef _DEBUG
    std::wstring message = L"Scenario: " + std::to_wstring(usage);
    const wchar_t* strings[] = { L"CredentialProvider::SetUsageScenario", message.c_str()};
    m_log->ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_INFO, strings);
#endif

    m_usage = usage;
    return IsSupportedScenario(usage, true) ? S_OK : E_NOTIMPL;
}


HRESULT CredentialProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* sc) {
    if (!sc)
        return E_POINTER;

#ifdef _DEBUG
    std::wstring message = L"AuthPackage: " + std::to_wstring(sc->ulAuthenticationPackage);
    const wchar_t* strings[] = { L"CredentialProvider::SetSerialization", message.c_str() };
    m_log->ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_INFO, strings);
#endif

    return S_OK;
}

HRESULT CredentialProvider::Advise(ICredentialProviderEvents* events, UINT_PTR adviseContext) {
#ifdef _DEBUG
    const wchar_t* strings[] = { L"CredentialProvider::Advise", L"" };
    m_log->ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_INFO, strings);
#endif

    UnAdvise();

    m_events = { events, adviseContext };
    return S_OK;
}

HRESULT CredentialProvider::UnAdvise() {
#ifdef _DEBUG
    const wchar_t* strings[] = { L"CredentialProvider::UnAdvise", L"" };
    m_log->ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_INFO, strings);
#endif

    m_events.context = 0;
    m_events.events.Release();
    return S_OK;
}

HRESULT CredentialProvider::GetFieldDescriptorCount(/*out*/DWORD* count) {
    if (!count)
        return E_POINTER;

    if (!m_view)
        return E_UNEXPECTED;

    *count = static_cast<DWORD>(m_view->fields.size());

#ifdef _DEBUG
    std::wstring message = std::to_wstring(*count) + L" fields";
    const wchar_t* strings[] = { L"CredentialProvider::GetFieldDescriptorCount", message.c_str()};
    m_log->ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_INFO, strings);
#endif
    return S_OK;
}

HRESULT CredentialProvider::GetFieldDescriptorAt(DWORD index, /*out*/CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) {
    if (!descriptor)
        return E_POINTER;

#ifdef _DEBUG
    std::wstring message = L"Index: " + std::to_wstring(index);
    const wchar_t* strings[] = { L"CredentialProvider::GetFieldDescriptorAt", message.c_str() };
    m_log->ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_INFO, strings);
#endif

    *descriptor = nullptr;
    if (!m_view || index >= m_view->fields.size())
        return E_INVALIDARG;

    auto copy = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    *copy = m_view->fields[index].descriptor;
    copy->pszLabel = DuplicateString(m_view->fields[index].descriptor.pszLabel);
    *descriptor = copy;
    return S_OK;
}

HRESULT CredentialProvider::GetCredentialCount(/*out*/DWORD* count, /*out*/DWORD* defaultIndex, /*out*/BOOL* autoLogonWithDefault) {
    if (!count || !defaultIndex || !autoLogonWithDefault)
        return E_POINTER;

    // Deferred initialization of m_authPkg & m_view.
    // Unable to do this in SetUsageScenario since it's not re-called after ICredentialProviderEvents::CredentialsChanged
    m_authPkg = 0; // default auth.pkg.
    if (MagicDriveCheck()) {
        ULONG authPkg = 0;
        HRESULT hr = GetAuthenticationPackage(&authPkg);
        if (SUCCEEDED(hr))
            m_authPkg = authPkg; // NoPasswordAuthPkg detected
    }

    m_view = CreateView(m_usage, (m_authPkg == 0));

    *count = static_cast<DWORD>(m_users.size());
    *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *autoLogonWithDefault = FALSE;

#ifdef _DEBUG
    std::wstring message = std::to_wstring(*count) + L" users. Password ";
    if (m_authPkg == 0)
        message += L"shown.";
    else
        message += L"hidden.";
    const wchar_t* strings[] = { L"CredentialProvider::GetCredentialCount", message.c_str()};
    m_log->ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_INFO, strings);
#endif
    return S_OK;
}

HRESULT CredentialProvider::GetCredentialAt(DWORD index, /*out*/ICredentialProviderCredential** credential) {
    if (!credential)
        return E_POINTER;

#ifdef _DEBUG
    const wchar_t* strings[] = { L"CredentialProvider::GetCredentialAt", L"" };
    m_log->ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_INFO, strings);
#endif

    *credential = nullptr;
    if (!m_view || index >= m_users.size())
        return E_INVALIDARG;

    std::wstring sid;
    {
        WCHAR* sidPtr = nullptr;
        HRESULT hr = m_users[index]->GetSid(&sidPtr);
        if (FAILED(hr))
            return hr;
        sid = sidPtr;
        CoTaskMemFree(sidPtr);
    }

    // cache lookup
    auto existing = m_credentials.find(sid);
    if (existing != m_credentials.end())
        return existing->second.CopyTo(credential);

    // add credential to cache
    CComObject<Credential>* instance = nullptr;
    HRESULT hr = CComObject<Credential>::CreateInstance(&instance);
    if (FAILED(hr))
        return hr;
    instance->AddRef();
    instance->Initialize(m_authPkg, m_view, sid, m_log);
    CComPtr<ICredentialProviderCredential> created;
    hr = instance->QueryInterface(&created);
    instance->Release();
    if (FAILED(hr))
        return hr;

    m_credentials.emplace(sid, created); // store in cache
    return created.CopyTo(credential); // assign output
}

HRESULT CredentialProvider::SetUserArray(ICredentialProviderUserArray* users) {
    if (!users)
        return E_POINTER;

    m_users.clear();
    m_credentials.clear();
    DWORD count = 0;
    HRESULT hr = users->GetCount(&count);
    if (FAILED(hr))
        return hr;

    for (DWORD index = 0; index < count; ++index) {
        CComPtr<ICredentialProviderUser> user;
        hr = users->GetAt(index, &user);
        if (FAILED(hr))
            return hr;
        m_users.push_back(std::move(user));
    }

#ifdef _DEBUG
    std::wstring message = std::to_wstring(m_users.size()) + L" users";
    const wchar_t* strings[] = { L"CredentialProvider::SetUserArray", message.c_str()};
    m_log->ReportInsertStrings(EVENTLOG_SUCCESS, CRED_PROVIDER_CATEGORY, MSG_CALL_INFO, strings);
#endif

    return S_OK;
}
