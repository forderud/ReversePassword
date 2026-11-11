#pragma once
#include <map>
#include <thread>
#include "ReversePasswordCredProv.hpp"
#include "../ReversePasswordEventProv/EventLogger.hpp"


struct AdviseCtx {
    winrt::com_ptr<ICredentialProviderEvents> events;
    std::atomic<UINT_PTR> context;
};

class CredentialProvider :
    public winrt::implements<CredentialProvider, ICredentialProvider, ICredentialProviderSetUserArray> {
public:
    CredentialProvider() {
        m_log = std::make_shared<EventLogger>(L"ReversePassword");
    }

    ~CredentialProvider() {
        UnAdvise();
     }

    HRESULT SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO usage, DWORD flags) override;
    HRESULT SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* sc) override;
    HRESULT Advise(ICredentialProviderEvents* events, UINT_PTR adviseContext) override;
    HRESULT UnAdvise() override;
    HRESULT GetFieldDescriptorCount(/*out*/DWORD* count) override;
    HRESULT GetFieldDescriptorAt(DWORD index, /*out*/CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override;
    HRESULT GetCredentialCount(/*out*/DWORD* count, /*out*/DWORD* defaultIndex, /*out*/BOOL* autoLogonWithDefault) override;
    HRESULT GetCredentialAt(DWORD index, /*out*/ICredentialProviderCredential** credential) override;
    HRESULT SetUserArray(ICredentialProviderUserArray* users) override;

private:
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_usage = CPUS_INVALID;
    ULONG m_authPkg = 0;
    std::shared_ptr<CredentialView> m_view;
    AdviseCtx m_events;
    std::vector<winrt::com_ptr<ICredentialProviderUser>> m_users;
    std::map<std::wstring, winrt::com_ptr<ICredentialProviderCredential>> m_credentials; // cache
    std::shared_ptr<EventLogger> m_log;
    std::thread                  m_listener;
};
