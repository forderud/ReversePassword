#pragma once
#include <map>
#include "ReversePassword.hpp"


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

OBJECT_ENTRY_AUTO(CLSID_ReversePassword, CredentialProvider)
