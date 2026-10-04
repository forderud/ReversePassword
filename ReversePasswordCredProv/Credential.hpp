#pragma once
#include "ReversePasswordCredProv.hpp"
#include "../ReversePasswordEventProv/EventLogger.hpp"
#include "../ReversePasswordEventProv/ReversePasswordEventProv.h"


class Credential :
    public CComObjectRootEx<CComMultiThreadModel>,
    public ICredentialProviderCredential2 {
public:
    BEGIN_COM_MAP(Credential)
        COM_INTERFACE_ENTRY(ICredentialProviderCredential)
        COM_INTERFACE_ENTRY(ICredentialProviderCredential2)
    END_COM_MAP()

    Credential() : m_log(L"ReversePassword") {
    }

    ~Credential() {
    }

    void Initialize(std::shared_ptr<CredentialView> view, std::wstring sid) {
        m_view = std::move(view);
        m_sid = sid;
    }

    HRESULT Advise(ICredentialProviderCredentialEvents* /*events*/) override { return S_OK; }
    HRESULT UnAdvise() override { return S_OK; }
    HRESULT SetSelected(BOOL* autoLogon) override;
    HRESULT SetDeselected() override;
    HRESULT GetFieldState(DWORD fieldId, CREDENTIAL_PROVIDER_FIELD_STATE* state, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactiveState) override;
    HRESULT GetStringValue(DWORD fieldId, WCHAR** value) override;
    HRESULT GetBitmapValue(DWORD fieldId, HBITMAP* bitmap) override;
    HRESULT GetCheckboxValue(DWORD /*fieldId*/, BOOL* /*checked*/, WCHAR** /*label*/) override { return E_NOTIMPL; }
    HRESULT GetSubmitButtonValue(DWORD fieldId, DWORD* adjacentTo) override;
    HRESULT GetComboBoxValueCount(DWORD /*fieldId*/, DWORD* /*itemCount*/, DWORD* /*selectedItem*/) override { return E_NOTIMPL; }
    HRESULT GetComboBoxValueAt(DWORD /*fieldId*/, DWORD /*item*/, WCHAR** /*value*/) override { return E_NOTIMPL; }
    HRESULT SetStringValue(DWORD fieldId, const WCHAR* value) override;
    HRESULT SetCheckboxValue(DWORD /*fieldId*/, BOOL /*checked*/) override { return E_NOTIMPL; }
    HRESULT SetComboBoxSelectedValue(DWORD /*fieldId*/, DWORD /*selectedItem*/) override { return E_NOTIMPL; }
    HRESULT CommandLinkClicked(DWORD /*fieldId*/) override { return E_NOTIMPL; }
    HRESULT GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization, WCHAR** statusText, CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
    HRESULT ReportResult(NTSTATUS status, NTSTATUS substatus, WCHAR** statusText, CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
    HRESULT GetUserSid(WCHAR** sid) override;

private:
    Field* GetField(DWORD fieldId) {
        if (!m_view)
            return nullptr;

        if (fieldId >= m_view->fields.size())
            return nullptr;

        return &m_view->fields[fieldId];
    }

    std::shared_ptr<CredentialView> m_view;
    std::wstring m_sid;
    EventLogger m_log;
};
