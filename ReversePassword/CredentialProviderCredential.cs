using CredProvider.Interop;
using System.Drawing;
using System.Reflection;
using System.Runtime.InteropServices;
using static ReversePassword.Constants;

namespace ReversePassword
{
    public class CredentialProviderCredential : ICredentialProviderCredential2
    {
        private readonly CredentialView _view;
        private readonly string _sid;
        private Bitmap _tileIcon;

        public CredentialProviderCredential(CredentialView view, string sid)
        {
            Logger.Write($"username={Common.GetNameFromSid(sid)}");

            _view = view;
            _sid = sid;
        }

        public virtual void Advise(ICredentialProviderCredentialEvents pcpce)
        {
            Logger.Write();

            if (pcpce is ICredentialProviderCredentialEvents2 ev2)
                Logger.Write("pcpce is ICredentialProviderCredentialEvents2");

            throw new NotImplementedException();
        }

        public virtual void UnAdvise()
        {
            Logger.Write();

            throw new NotImplementedException();
        }

        public virtual void SetSelected(out int pbAutoLogon)
        {
            Logger.Write();

            //Set this to 1 if you would like GetSerialization called immediately on selection
            pbAutoLogon = 0;
        }

        public virtual void SetDeselected()
        {
            Logger.Write();

            throw new NotImplementedException();
        }

        public virtual void GetFieldState(
            uint fieldID,
            out _CREDENTIAL_PROVIDER_FIELD_STATE pcpfs,
            out _CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE pcpfis)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            CredentialDescriptor field = _view.GetField(fieldID);

            Logger.Write($"Returning field state: {field.State}, interactiveState: None");
            pcpfs = field.State;
            pcpfis = _CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE.CPFIS_NONE;
        }

        public virtual void GetStringValue(uint fieldID, out string ppsz)
        {
            ppsz = (string)_view.GetField(fieldID).Value;
            Logger.Write($"dwFieldID:{fieldID}, ppsz={ppsz}");
        }

        public virtual void GetBitmapValue(uint fieldID, out IntPtr phbmp)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            try
            {
                TryLoadUserIcon();
            }
            catch (Exception ex) 
            {
                Logger.Write("Error: " + ex);
            }

            phbmp = _tileIcon?.GetHbitmap() ?? IntPtr.Zero;
        }

        private void TryLoadUserIcon()
        {
            if (_tileIcon == null)
            {
                var fileName = "ReversePassword.tile-icon.bmp";
                var assembly = Assembly.GetExecutingAssembly();
                var stream = assembly.GetManifestResourceStream(fileName);

                _tileIcon = (Bitmap)Image.FromStream(stream);
            }
        }

        public virtual void GetCheckboxValue(uint fieldID, out int pbChecked, out string ppszLabel)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            pbChecked = 0;
            ppszLabel = "";

            throw new NotImplementedException();
        }

        public virtual void GetSubmitButtonValue(uint fieldID, out uint adjacentTo)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            adjacentTo = 0;

            throw new NotImplementedException();
        }

        public virtual void GetComboBoxValueCount(uint fieldID, out uint pcItems, out uint selectedItem)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            pcItems = 0;
            selectedItem = 0;

            throw new NotImplementedException();
        }

        public virtual void GetComboBoxValueAt(uint fieldID, uint item, out string ppszItem)
        {
            Logger.Write($"dwFieldID: {fieldID}; dwItem: {item}");

            ppszItem = "";

            throw new NotImplementedException();
        }

        public virtual void SetStringValue(uint fieldID, string psz)
        {
            Logger.Write($"dwFieldID: {fieldID}; psz: {psz}");

            _view.GetField(fieldID).Value = psz;
        }

        public virtual void SetCheckboxValue(uint fieldID, int bChecked)
        {
            Logger.Write($"dwFieldID: {fieldID}; bChecked: {bChecked}");

            throw new NotImplementedException();
        }

        public virtual void SetComboBoxSelectedValue(uint fieldID, uint selectedItem)
        {
            Logger.Write($"dwFieldID: {fieldID}; dwSelectedItem: {selectedItem}");

            throw new NotImplementedException();
        }

        public virtual void CommandLinkClicked(uint fieldID)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            throw new NotImplementedException();
        }

        public virtual void GetSerialization(
            out _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE pcpgsr,
            out _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION pcpcs,
            out string ppszOptionalStatusText,
            out _CREDENTIAL_PROVIDER_STATUS_ICON pcpsiOptionalStatusIcon)
        {
            var usage = _view.Provider.GetUsage();
            Logger.Write($"usage: {usage}");

            pcpgsr = _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            pcpcs = new _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION();
            ppszOptionalStatusText = "";
            pcpsiOptionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE;

            //Serialization can be called before the user has entered any values. Only applies to logon usage scenarios
            if (usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_LOGON
                || usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_UNLOCK_WORKSTATION
                || usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CREDUI) // triggered by CredUIPromptForWindowsCredentials
            {
                //Determine the authentication package
                Common.RetrieveNegotiateAuthPackage(out var authPackage);

                //Only credential packing for msv1_0 is supported using this code
                Logger.Write($"Got authentication package: {authPackage}. Only local authenticsation package 0 (msv1_0) is supported.");

                //Get username and password
                var username = Common.GetNameFromSid(_sid);
                var password = (string)_view.GetField(2).Value;

                {
                    // reverse password
                    char[] passwordArray = password.ToCharArray();
                    Array.Reverse(passwordArray);
                    password = new string(passwordArray);
                }

                Logger.Write($"Preparing to serialise credential with username={username} and password={password}");
                pcpgsr = _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_RETURN_CREDENTIAL_FINISHED;
                pcpcs = new _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION();

                var inCredSize = 0;
                var inCredBuffer = Marshal.AllocCoTaskMem(0);

                if (!PInvoke.CredPackAuthenticationBuffer(0, username, password, inCredBuffer, ref inCredSize))
                {
                    Marshal.FreeCoTaskMem(inCredBuffer);
                    inCredBuffer = Marshal.AllocCoTaskMem(inCredSize);

                    if (PInvoke.CredPackAuthenticationBuffer(0, username, password, inCredBuffer, ref inCredSize))
                    {
                        ppszOptionalStatusText = string.Empty;
                        pcpsiOptionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_SUCCESS;

                        pcpcs.clsidCredentialProvider = Guid.Parse(Constants.CredentialProvider_CLSID);
                        pcpcs.rgbSerialization = inCredBuffer;
                        pcpcs.cbSerialization = (uint)inCredSize;
                        pcpcs.ulAuthenticationPackage = authPackage;
                        return;
                    }

                    ppszOptionalStatusText = "Failed to pack credentials";
                    pcpsiOptionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_ERROR;
                    throw new Exception();
                }
            }
            else if (usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD)
            {
                //Implement code to change password here. This is not handled natively.
                pcpgsr = _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_FINISHED;
                pcpcs = new _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION();
                ppszOptionalStatusText = "Password changed success message.";
                pcpsiOptionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_SUCCESS;
            }

            Logger.Write("Returning S_OK");
        }

        public virtual void ReportResult(
            int ntsStatus,
            int ntsSubstatus,
            out string ppszOptionalStatusText,
            out _CREDENTIAL_PROVIDER_STATUS_ICON pcpsiOptionalStatusIcon)
        {
            Logger.Write($"ntsStatus: {ntsStatus}; ntsSubstatus: {ntsSubstatus}");

            ppszOptionalStatusText = "";
            pcpsiOptionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE;
        }

        public virtual void GetUserSid(out string sid)
        {
            sid = _sid;

            Logger.Write($"username: {Common.GetNameFromSid(sid)}");
        }
    }
}
