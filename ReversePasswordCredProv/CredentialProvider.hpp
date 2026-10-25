#pragma once
#include <map>
#include "ReversePasswordCredProv.hpp"
#include "../ReversePasswordEventProv/EventLogger.hpp"


struct AdviseCtx {
    CComPtr<ICredentialProviderEvents> events;
    UINT_PTR context;
};

class CredentialProvider :
    public CComObjectRootEx<CComMultiThreadModel>,
    public CComCoClass<CredentialProvider, &CLSID_ReversePasswordCredProv>,
    public ICredentialProvider,
    public ICredentialProviderSetUserArray {
public:
    CredentialProvider() {
        m_log = std::make_shared<EventLogger>(L"ReversePassword");
    }

    ~CredentialProvider() {
        UnAdvise();
     }

    HRESULT SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO usage, DWORD flags) override;
    HRESULT SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* /*sc*/) override { return S_OK; }
    HRESULT Advise(ICredentialProviderEvents* events, UINT_PTR adviseContext) override;
    HRESULT UnAdvise() override;
    HRESULT GetFieldDescriptorCount(DWORD* count) override;
    HRESULT GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override;
    HRESULT GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogonWithDefault) override;
    HRESULT GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) override;
    HRESULT SetUserArray(ICredentialProviderUserArray* users) override;

    DECLARE_REGISTRY_RESOURCEID(IDR_REVERSEPASSWORD)

    BEGIN_COM_MAP(CredentialProvider)
        COM_INTERFACE_ENTRY(ICredentialProvider)
        COM_INTERFACE_ENTRY(ICredentialProviderSetUserArray)
    END_COM_MAP()

private:
    ULONG m_authPkg = 0;
    std::shared_ptr<CredentialView> m_view;
    AdviseCtx m_events;
    std::vector<CComPtr<ICredentialProviderUser>> m_users;
    std::map<std::wstring, CComPtr<ICredentialProviderCredential>> m_credentials;
    std::shared_ptr<EventLogger> m_log;
};

OBJECT_ENTRY_AUTO(CLSID_ReversePasswordCredProv, CredentialProvider)
