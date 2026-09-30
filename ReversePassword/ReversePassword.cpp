#include "ReversePassword.hpp"
#include "resource.h"

#include <comdef.h> // for _com_error
#include <lm.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <wincred.h>

#include <map>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Secur32.lib")

class ReversePasswordModule final : public CAtlDllModuleT<ReversePasswordModule>
{
};

ReversePasswordModule g_module;

namespace {

constexpr DWORD kNoDefaultCredential = 0xffffffff;
constexpr DWORD ICON_FIELD = 0;
constexpr DWORD USER_NAME_FIELD = 1;
constexpr DWORD PASSWORD_FIELD = 2;
constexpr DWORD NEW_PASSWORD_FIELD = 3;
constexpr DWORD SUBMIT_BUTTON_FIELD = 4;
constexpr NTSTATUS kStatusSuccess = static_cast<NTSTATUS>(0);

struct Field {
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR descriptor{};
    CREDENTIAL_PROVIDER_FIELD_STATE state{};
    std::variant<std::wstring, DWORD> value;
};

struct CredentialView {
    CREDENTIAL_PROVIDER_USAGE_SCENARIO usage{};
    std::vector<Field> fields;
};

bool IsSupportedScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO usage) {
    switch (usage) {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
        return true;

    case CPUS_INVALID:
    case CPUS_PLAP:
    default:
        return false;
    }
}

std::shared_ptr<CredentialView> CreateView(CREDENTIAL_PROVIDER_USAGE_SCENARIO usage) {
    if (!IsSupportedScenario(usage))
        return {};

    auto view = std::make_shared<CredentialView>();
    view->usage = usage;
    const auto userNameState = usage == CPUS_CREDUI ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
    const auto newPasswordState = usage == CPUS_CHANGE_PASSWORD ? CPFS_DISPLAY_IN_BOTH : CPFS_HIDDEN;
    const DWORD submitAdjacentTo = usage == CPUS_CHANGE_PASSWORD ? NEW_PASSWORD_FIELD : PASSWORD_FIELD;

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

    addField(CPFT_TILE_IMAGE, L"Icon", CPFS_DISPLAY_IN_BOTH, {});
    addField(CPFT_EDIT_TEXT, L"Username", userNameState, {});
    addField(CPFT_PASSWORD_TEXT, L"Password", CPFS_DISPLAY_IN_SELECTED_TILE, {});
    addField(CPFT_PASSWORD_TEXT, L"New password", newPasswordState, {});
    addField(CPFT_SUBMIT_BUTTON, L"Submit", CPFS_DISPLAY_IN_SELECTED_TILE, submitAdjacentTo);
    addField(CPFT_LARGE_TEXT, nullptr, CPFS_DISPLAY_IN_BOTH, L"Reverse Password");
    return view;
}

WCHAR* DuplicateString(const WCHAR* source) {
    if (!source)
        return nullptr;

    WCHAR* result = nullptr;
    HRESULT hr = SHStrDupW(source, &result); // uses CoTaskMemAlloc internally
    if (FAILED(hr))
        return nullptr;

    return result;
}

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
    if (status != kStatusSuccess)
        return HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));

    const auto lookup = [lsa, package](const char* name)
    {
        LSA_STRING packageName{};
        packageName.Buffer = const_cast<PCHAR>(name);
        packageName.Length = static_cast<USHORT>(strlen(name));
        packageName.MaximumLength = packageName.Length;
        return LsaLookupAuthenticationPackage(lsa, &packageName, package);
    };

    status = lookup("NoPasswordAuthPkg"); // use NoPasswordAuthPkg if installed
    if (status != kStatusSuccess)
        status = lookup("Negotiate"); // falback to Negotiate
    LsaDeregisterLogonProcess(lsa);
    return status == kStatusSuccess ? S_OK : HRESULT_FROM_WIN32(LsaNtStatusToWinError(status));
}

std::wstring Reverse(std::wstring value) {
    std::reverse(value.begin(), value.end());
    return value;
}

HRESULT CredPackAuthenticationBufferWrap(const WCHAR* userName, const WCHAR* password, BYTE** buffer, DWORD* size) {
    if (!buffer || !size)
        return E_POINTER;

    *buffer = nullptr;
    *size = 0;

    DWORD required = 0;
    CredPackAuthenticationBufferW(0, const_cast<WCHAR*>(userName), const_cast<WCHAR*>(password), nullptr, &required);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return HRESULT_FROM_WIN32(GetLastError());

    auto packed = static_cast<BYTE*>(CoTaskMemAlloc(required));
    if (!CredPackAuthenticationBufferW(0, const_cast<WCHAR*>(userName), const_cast<WCHAR*>(password), packed, &required))
    {
        const HRESULT result = HRESULT_FROM_WIN32(GetLastError());
        CoTaskMemFree(packed);
        return result;
    }
    *buffer = packed;
    *size = required;
    return S_OK;
}
}

class Credential :
    public CComObjectRootEx<CComMultiThreadModel>,
    public ICredentialProviderCredential2 {
public:
    BEGIN_COM_MAP(Credential)
        COM_INTERFACE_ENTRY(ICredentialProviderCredential)
        COM_INTERFACE_ENTRY(ICredentialProviderCredential2)
    END_COM_MAP()

    void Initialize(std::shared_ptr<CredentialView> view, const WCHAR* sid) {
        m_view = std::move(view);
        m_sid = sid;
    }

    HRESULT Advise(ICredentialProviderCredentialEvents*) override { return S_OK; }
    HRESULT UnAdvise() override { return S_OK; }
    HRESULT SetSelected(BOOL* autoLogon) override;
    HRESULT SetDeselected() override;
    HRESULT GetFieldState(DWORD fieldId, CREDENTIAL_PROVIDER_FIELD_STATE* state,
                             CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactiveState) override;
    HRESULT GetStringValue(DWORD fieldId, WCHAR** value) override;
    HRESULT GetBitmapValue(DWORD fieldId, HBITMAP* bitmap) override;
    HRESULT GetCheckboxValue(DWORD, BOOL* /*checked*/, WCHAR** /*label*/) override { return E_NOTIMPL; }
    HRESULT GetSubmitButtonValue(DWORD fieldId, DWORD* adjacentTo) override;
    HRESULT GetComboBoxValueCount(DWORD, DWORD*, DWORD*) override { return E_NOTIMPL; }
    HRESULT GetComboBoxValueAt(DWORD, DWORD, WCHAR**) override { return E_NOTIMPL; }
    HRESULT SetStringValue(DWORD fieldId, const WCHAR* value) override;
    HRESULT SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
    HRESULT SetComboBoxSelectedValue(DWORD, DWORD) override { return E_NOTIMPL; }
    HRESULT CommandLinkClicked(DWORD) override { return E_NOTIMPL; }
    HRESULT GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
                                CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
                                WCHAR** statusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
    HRESULT ReportResult(NTSTATUS status, NTSTATUS substatus, WCHAR** statusText,
                            CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
    HRESULT GetUserSid(WCHAR** sid) override { *sid = DuplicateString(m_sid.c_str()); return *sid ? S_OK : E_POINTER; }

private:
    Field* GetField(DWORD fieldId) {
        return m_view && fieldId < m_view->fields.size() ? &m_view->fields[fieldId] : nullptr;
    }

    std::shared_ptr<CredentialView> m_view;
    std::wstring m_sid;
};

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
        HRESULT result = GetAccountName(m_sid.c_str(), accountName);
        if (FAILED(result))
            return result;

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
        return S_OK;
    }

    // CPUS_LOGON, CPUS_UNLOCK_WORKSTATION or CPUS_CREDUI logic
    ULONG authenticationPackage = 0;
    HRESULT result = GetAuthenticationPackage(&authenticationPackage);
    if (FAILED(result))
        return result;

    std::wstring userName;
    if (m_view->usage == CPUS_CREDUI)
        userName = std::get<std::wstring>(GetField(USER_NAME_FIELD)->value);
    else if (FAILED(result = GetAccountName(m_sid.c_str(), userName)))
        return result;

    const std::wstring password = Reverse(std::get<std::wstring>(GetField(PASSWORD_FIELD)->value));
    result = CredPackAuthenticationBufferWrap(userName.c_str(), password.c_str(), &serialization->rgbSerialization,
                             &serialization->cbSerialization);
    if (FAILED(result)) {
        *statusIcon = CPSI_ERROR;
        *statusText = DuplicateString(L"Failed to pack credentials.");
        return result;
    }

    serialization->clsidCredentialProvider = CLSID_ReversePassword;
    serialization->ulAuthenticationPackage = authenticationPackage;
    *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
    *statusIcon = CPSI_SUCCESS;
    return S_OK;
}

HRESULT Credential::ReportResult(NTSTATUS status, NTSTATUS substatus, WCHAR** statusText,
                                      CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) {
    if (!statusText || !statusIcon)
        return E_POINTER;

    *statusText = nullptr;
    *statusIcon = CPSI_NONE;

    if (status != kStatusSuccess) {
        std::wstring message = L"Logon failed with status: ";
        message += _com_error(status).ErrorMessage();
        message += L", substatus: ";
        message += _com_error(substatus).ErrorMessage();
        *statusText = DuplicateString(message.c_str());
    }
    return S_OK;
}

class CredentialProvider :
    public CComObjectRootEx<CComMultiThreadModel>,
    public CComCoClass<CredentialProvider, &CLSID_ReversePassword>,
    public ICredentialProvider,
    public ICredentialProviderSetUserArray {
public:
    DECLARE_REGISTRY_RESOURCEID(IDR_REVERSEPASSWORD)

    BEGIN_COM_MAP(CredentialProvider)
        COM_INTERFACE_ENTRY(ICredentialProvider)
        COM_INTERFACE_ENTRY(ICredentialProviderSetUserArray)
    END_COM_MAP()

    HRESULT SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO usage, DWORD flags) override;
    HRESULT SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override { return S_OK; }
    HRESULT Advise(ICredentialProviderEvents* events, UINT_PTR) override { m_events = events; return S_OK; }
    HRESULT UnAdvise() override { m_events.Release(); return S_OK; }
    HRESULT GetFieldDescriptorCount(DWORD* count) override;
    HRESULT GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override;
    HRESULT GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogonWithDefault) override;
    HRESULT GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) override;
    HRESULT SetUserArray(ICredentialProviderUserArray* users) override;

private:
    std::shared_ptr<CredentialView> m_view;
    CComPtr<ICredentialProviderEvents> m_events;
    std::vector<CComPtr<ICredentialProviderUser>> m_users;
    std::map<std::wstring, CComPtr<ICredentialProviderCredential>> m_credentials;
};

HRESULT CredentialProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO usage, DWORD /*flags*/) {
    m_view = CreateView(usage);
    m_credentials.clear();
    return m_view ? S_OK : E_NOTIMPL;
}

HRESULT CredentialProvider::GetFieldDescriptorCount(DWORD* count) {
    if (!count)
        return E_POINTER;

    if (!m_view)
        return E_UNEXPECTED;

    *count = static_cast<DWORD>(m_view->fields.size());
    return S_OK;
}

HRESULT CredentialProvider::GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) {
    if (!descriptor)
        return E_POINTER;

    *descriptor = nullptr;
    if (!m_view || index >= m_view->fields.size())
        return E_INVALIDARG;

    auto copy = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    *copy = m_view->fields[index].descriptor;
    copy->pszLabel = DuplicateString(m_view->fields[index].descriptor.pszLabel);
    *descriptor = copy;
    return S_OK;
}

HRESULT CredentialProvider::GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogonWithDefault) {
    if (!count || !defaultIndex || !autoLogonWithDefault)
        return E_POINTER;

    *count = static_cast<DWORD>(m_users.size());
    *defaultIndex = kNoDefaultCredential;
    *autoLogonWithDefault = FALSE;
    return S_OK;
}

HRESULT CredentialProvider::GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) {
    if (!credential)
        return E_POINTER;

    *credential = nullptr;
    if (!m_view || index >= m_users.size())
        return E_INVALIDARG;

    WCHAR* sid = nullptr;
    HRESULT hr = m_users[index]->GetSid(&sid);
    if (FAILED(hr))
        return hr;
    const std::wstring sidValue(sid);
    CoTaskMemFree(sid);

    // cache lookup
    auto existing = m_credentials.find(sidValue);
    if (existing != m_credentials.end())
        return existing->second.CopyTo(credential);

    // add credential to cache
    CComObject<Credential>* instance = nullptr;
    hr = CComObject<Credential>::CreateInstance(&instance);
    if (FAILED(hr))
        return hr;
    instance->AddRef();
    instance->Initialize(m_view, sidValue.c_str());
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
    return S_OK;
}

OBJECT_ENTRY_AUTO(CLSID_ReversePassword, CredentialProvider)


extern "C" BOOL WINAPI DllMain(HINSTANCE /*instance*/, DWORD reason, LPVOID reserved) {
    return g_module.DllMain(reason, reserved);
}

STDAPI DllCanUnloadNow() { return g_module.DllCanUnloadNow(); }
STDAPI DllGetClassObject(REFCLSID clsid, REFIID iid, LPVOID* object) { return g_module.DllGetClassObject(clsid, iid, object); }
STDAPI DllRegisterServer() { return g_module.DllRegisterServer(); }
STDAPI DllUnregisterServer() { return g_module.DllUnregisterServer(); }
