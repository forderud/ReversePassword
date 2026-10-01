#include "ReversePassword.hpp"
#include <map>
#include "Credential.Hpp"

#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Secur32.lib")

class ReversePasswordModule final : public CAtlDllModuleT<ReversePasswordModule>
{
};

ReversePasswordModule g_module;

namespace {

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

    addField(CPFT_TILE_IMAGE, L"Icon", CPFS_DISPLAY_IN_BOTH, {}); // ICON_FIELD
    addField(CPFT_EDIT_TEXT, L"Username", userNameState, {}); // USER_NAME_FIELD
    addField(CPFT_PASSWORD_TEXT, L"Password", CPFS_DISPLAY_IN_SELECTED_TILE, {}); // PASSWORD_FIELD
    addField(CPFT_PASSWORD_TEXT, L"New password", newPasswordState, {}); // NEW_PASSWORD_FIELD
    addField(CPFT_SUBMIT_BUTTON, L"Submit", CPFS_DISPLAY_IN_SELECTED_TILE, submitAdjacentTo); // SUBMIT_BUTTON_FIELD
    addField(CPFT_LARGE_TEXT, nullptr, CPFS_DISPLAY_IN_BOTH, L"Reverse Password");
    return view;
}

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
    *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *autoLogonWithDefault = FALSE;
    return S_OK;
}

HRESULT CredentialProvider::GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) {
    if (!credential)
        return E_POINTER;

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
    instance->Initialize(m_view, sid);
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
STDAPI DllRegisterServer() { return g_module.DllRegisterServer(/*typelib*/false); }
STDAPI DllUnregisterServer() { return g_module.DllUnregisterServer(/*typelib*/false); }
