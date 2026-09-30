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

class ReversePasswordModule final : public ATL::CAtlDllModuleT<ReversePasswordModule>
{
};

ReversePasswordModule g_module;

namespace {

constexpr DWORD kNoDefaultCredential = 0xffffffff;
constexpr DWORD kTileImageField = 0;
constexpr DWORD kUserNameField = 1;
constexpr DWORD kPasswordField = 2;
constexpr DWORD kNewPasswordField = 3;
constexpr DWORD kSubmitButtonField = 4;
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
    const DWORD submitAdjacentTo = usage == CPUS_CHANGE_PASSWORD ? kNewPasswordField : kPasswordField;

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
    public ATL::CComObjectRootEx<ATL::CComMultiThreadModel>,
    public ICredentialProviderCredential2 {
public:
    BEGIN_COM_MAP(Credential)
        COM_INTERFACE_ENTRY(ICredentialProviderCredential)
        COM_INTERFACE_ENTRY(ICredentialProviderCredential2)
    END_COM_MAP()

    HRESULT Initialize(std::shared_ptr<CredentialView> view, const WCHAR* sid) {
        view_ = std::move(view);
        sid_ = sid;
        return S_OK;
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
    HRESULT GetUserSid(WCHAR** sid) override { *sid = DuplicateString(sid_.c_str()); return *sid ? S_OK : E_POINTER; }

private:
    Field* GetField(DWORD fieldId) {
        return view_ && fieldId < view_->fields.size() ? &view_->fields[fieldId] : nullptr;
    }

    std::shared_ptr<CredentialView> view_;
    std::wstring sid_;
};

HRESULT Credential::SetSelected(BOOL* autoLogon) {
    if (!autoLogon)
        return E_POINTER;

    *autoLogon = FALSE;
    return S_OK;
}

HRESULT Credential::SetDeselected() {
    if (Field* password = GetField(kPasswordField))
        password->value = {};

    if (Field* password = GetField(kNewPasswordField))
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
    if (fieldId != kTileImageField || !bitmap)
        return E_INVALIDARG;

    *bitmap = static_cast<HBITMAP>(LoadImageW(ATL::_AtlBaseModule.GetModuleInstance(), MAKEINTRESOURCEW(IDB_TILE_ICON),
                                               IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION));
    return *bitmap ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

HRESULT Credential::GetSubmitButtonValue(DWORD fieldId, DWORD* adjacentTo) {
    if (fieldId != kSubmitButtonField || !adjacentTo)
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

    if (view_->usage == CPUS_CHANGE_PASSWORD) {
        // pasword change logic
        std::wstring accountName;
        HRESULT result = GetAccountName(sid_.c_str(), accountName);
        if (FAILED(result))
            return result;

        const size_t separator = accountName.find(L'\\');
        if (separator == std::wstring::npos)
            return E_FAIL;

        const std::wstring oldPassword = Reverse(std::get<std::wstring>(GetField(kPasswordField)->value));
        const std::wstring newPassword = Reverse(std::get<std::wstring>(GetField(kNewPasswordField)->value));
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
    if (view_->usage == CPUS_CREDUI)
        userName = std::get<std::wstring>(GetField(kUserNameField)->value);
    else if (FAILED(result = GetAccountName(sid_.c_str(), userName)))
        return result;

    const std::wstring password = Reverse(std::get<std::wstring>(GetField(kPasswordField)->value));
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
    public ATL::CComObjectRootEx<ATL::CComMultiThreadModel>,
    public ATL::CComCoClass<CredentialProvider, &CLSID_ReversePassword>,
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
    HRESULT Advise(ICredentialProviderEvents* events, UINT_PTR) override { events_ = events; return S_OK; }
    HRESULT UnAdvise() override { events_.Release(); return S_OK; }
    HRESULT GetFieldDescriptorCount(DWORD* count) override;
    HRESULT GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override;
    HRESULT GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogonWithDefault) override;
    HRESULT GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) override;
    HRESULT SetUserArray(ICredentialProviderUserArray* users) override;

private:
    std::shared_ptr<CredentialView> view_;
    ATL::CComPtr<ICredentialProviderEvents> events_;
    std::vector<ATL::CComPtr<ICredentialProviderUser>> users_;
    std::map<std::wstring, ATL::CComPtr<ICredentialProviderCredential>> credentials_;
};

HRESULT CredentialProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO usage, DWORD /*flags*/) {
    view_ = CreateView(usage);
    credentials_.clear();
    return view_ ? S_OK : E_NOTIMPL;
}

HRESULT CredentialProvider::GetFieldDescriptorCount(DWORD* count) {
    if (!count)
        return E_POINTER;

    if (!view_)
        return E_UNEXPECTED;

    *count = static_cast<DWORD>(view_->fields.size());
    return S_OK;
}

HRESULT CredentialProvider::GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) {
    if (!descriptor)
        return E_POINTER;

    *descriptor = nullptr;
    if (!view_ || index >= view_->fields.size())
        return E_INVALIDARG;

    auto copy = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    *copy = view_->fields[index].descriptor;
    copy->pszLabel = DuplicateString(view_->fields[index].descriptor.pszLabel);
    *descriptor = copy;
    return S_OK;
}

HRESULT CredentialProvider::GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogonWithDefault) {
    if (!count || !defaultIndex || !autoLogonWithDefault)
        return E_POINTER;

    *count = static_cast<DWORD>(users_.size());
    *defaultIndex = kNoDefaultCredential;
    *autoLogonWithDefault = FALSE;
    return S_OK;
}

HRESULT CredentialProvider::GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) {
    if (!credential)
        return E_POINTER;

    *credential = nullptr;
    if (!view_ || index >= users_.size())
        return E_INVALIDARG;

    WCHAR* sid = nullptr;
    HRESULT result = users_[index]->GetSid(&sid);
    if (FAILED(result))
        return result;
    const std::wstring sidValue(sid);
    CoTaskMemFree(sid);

    // cache lookup
    auto existing = credentials_.find(sidValue);
    if (existing == credentials_.end()) {
        // add credential to cache
        ATL::CComObject<Credential>* object = nullptr;
        result = ATL::CComObject<Credential>::CreateInstance(&object);
        if (FAILED(result))
            return result;
        object->AddRef();
        result = object->Initialize(view_, sidValue.c_str());
        if (SUCCEEDED(result))
            result = object->QueryInterface(credential);
        if (SUCCEEDED(result))
            credentials_.emplace(sidValue, object);
        object->Release();
        return result;
    }
    return existing->second.CopyTo(credential);
}

HRESULT CredentialProvider::SetUserArray(ICredentialProviderUserArray* users) {
    if (!users)
        return E_POINTER;

    users_.clear();
    credentials_.clear();
    DWORD count = 0;
    HRESULT result = users->GetCount(&count);
    if (FAILED(result))
        return result;

    for (DWORD index = 0; index < count; ++index) {
        ATL::CComPtr<ICredentialProviderUser> user;
        result = users->GetAt(index, &user);
        if (FAILED(result))
            return result;
        users_.push_back(std::move(user));
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
