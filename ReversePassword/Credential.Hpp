#pragma once
#include "ReversePassword.hpp"


class Credential :
    public CComObjectRootEx<CComMultiThreadModel>,
    public ICredentialProviderCredential2 {
public:
    BEGIN_COM_MAP(Credential)
        COM_INTERFACE_ENTRY(ICredentialProviderCredential)
        COM_INTERFACE_ENTRY(ICredentialProviderCredential2)
    END_COM_MAP()

    void Initialize(std::shared_ptr<CredentialView> view, std::wstring sid) {
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
        if (!m_view)
            return nullptr;

        if (fieldId >= m_view->fields.size())
            return nullptr;

        return &m_view->fields[fieldId];
    }

    std::shared_ptr<CredentialView> m_view;
    std::wstring m_sid;
};
