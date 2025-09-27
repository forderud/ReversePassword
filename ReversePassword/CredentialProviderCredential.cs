using CredProvider.Interop;
using System.Drawing;
using System.Reflection;

namespace ReversePassword
{
    public class CredentialProviderCredential : ICredentialProviderCredential2
    {
        private readonly CredentialView _view;
        private readonly string _sid;
        private Bitmap _tileIcon;

        public CredentialProviderCredential(CredentialView view, string sid)
        {
            Logger.Write($"username: {Common.GetNameFromSid(sid)}");

            _view = view;
            _sid = sid;
        }

        public virtual void Advise(ICredentialProviderCredentialEvents cpce)
        {
            Logger.Write();

            if (cpce is ICredentialProviderCredentialEvents2 ev2)
                Logger.Write("pcpce is ICredentialProviderCredentialEvents2");

            throw new NotImplementedException();
        }

        public virtual void UnAdvise()
        {
            Logger.Write();

            throw new NotImplementedException();
        }

        public virtual void SetSelected(out int autoLogon)
        {
            Logger.Write();

            //Set this to 1 if you would like GetSerialization called immediately on selection
            autoLogon = 0;
        }

        public virtual void SetDeselected()
        {
            Logger.Write();

            throw new NotImplementedException();
        }

        public virtual void GetFieldState(
            uint fieldID,
            out _CREDENTIAL_PROVIDER_FIELD_STATE cpfs,
            out _CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            CredentialDescriptor field = _view.GetField(fieldID);

            cpfs = field.State;
            cpfis = _CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE.CPFIS_NONE; // NONE, READONLY, DISABLED or FOCUSED
            Logger.Write($"Returning field state: {cpfs}, interactiveState: {cpfis}");
        }

        public virtual void GetStringValue(uint fieldID, out string val)
        {
            val = (string)_view.GetField(fieldID).Value;
            Logger.Write($"dwFieldID: {fieldID}, ppsz: {val}");
        }

        public virtual void GetBitmapValue(uint fieldID, out IntPtr bmp)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            try
            {
                if (_tileIcon == null)
                {
                    var fileName = "ReversePassword.tile-icon.bmp";
                    var assembly = Assembly.GetExecutingAssembly();
                    var stream = assembly.GetManifestResourceStream(fileName);

                    _tileIcon = (Bitmap)Image.FromStream(stream);
                }
            }
            catch (Exception ex) 
            {
                Logger.Write("Error: " + ex);
            }

            bmp = _tileIcon?.GetHbitmap() ?? IntPtr.Zero;
        }

        public virtual void GetCheckboxValue(uint fieldID, out int isChecked, out string label)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            isChecked = 0;
            label = "";

            throw new NotImplementedException();
        }

        public virtual void GetSubmitButtonValue(uint fieldID, out uint adjacentTo)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            adjacentTo = 0;

            throw new NotImplementedException();
        }

        public virtual void GetComboBoxValueCount(uint fieldID, out uint itemCount, out uint selectedItem)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            itemCount = 0;
            selectedItem = 0;

            throw new NotImplementedException();
        }

        public virtual void GetComboBoxValueAt(uint fieldID, uint item, out string val)
        {
            Logger.Write($"dwFieldID: {fieldID}; dwItem: {item}");

            val = "";

            throw new NotImplementedException();
        }

        public virtual void SetStringValue(uint fieldID, string val)
        {
            Logger.Write($"dwFieldID: {fieldID}; psz: {val}");

            _view.GetField(fieldID).Value = val;
        }

        public virtual void SetCheckboxValue(uint fieldID, int isChecked)
        {
            Logger.Write($"dwFieldID: {fieldID}; bChecked: {isChecked}");

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
            out _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE cpgsr,
            out _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs,
            out string optionalStatusText,
            out _CREDENTIAL_PROVIDER_STATUS_ICON optionalStatusIcon)
        {
            var usage = _view.Usage;
            Logger.Write($"usage: {usage}");

            cpgsr = _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            cpcs = new _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION();
            optionalStatusText = "";
            optionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE;

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

                Logger.Write($"Preparing to serialise credential with username: {username} and password: {password}");
                cpgsr = _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_RETURN_CREDENTIAL_FINISHED;
                cpcs = new _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION();

                IntPtr inCredBuffer = 0;
                int inCredSize = 0;
                if (!PInvoke.CredPackAuthenticationBufferWrap(0, username, password, out inCredBuffer, out inCredSize))
                {
                    optionalStatusText = "Failed to pack credentials";
                    optionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_ERROR;
                    throw new Exception();
                }

                optionalStatusText = string.Empty;
                optionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_SUCCESS;

                cpcs.clsidCredentialProvider = Guid.Parse(Constants.CredentialProvider_CLSID);
                cpcs.rgbSerialization = inCredBuffer;
                cpcs.cbSerialization = (uint)inCredSize;
                cpcs.ulAuthenticationPackage = authPackage;
            }
            else if (usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD)
            {
                // Password change logic..
                string username = Common.GetNameFromSid(_sid);
                string oldPwd = (string)_view.GetField(2).Value;
                string newPwd = (string)_view.GetField(3).Value;

                uint res = PInvoke.NetUserChangePassword(null, username, oldPwd, newPwd);
                if (res != Constants.NERR_Success)
                {
                    if (res == Constants.ERROR_ACCESS_DENIED)
                        optionalStatusText = "ERROR: Access denied.";
                    else if (res == Constants.ERROR_INVALID_PASSWORD)
                        optionalStatusText = "ERROR: Invalid password.";
                    else if (res == Constants.ERROR_CANT_ACCESS_DOMAIN_INFO)
                        optionalStatusText = "ERROR: Configuration information could not be read from the domain controller, either because the machine is unavailable, or access has been denied.";
                    else if (res == Constants.NERR_UserNotFound)
                        optionalStatusText = "ERROR: User name not found.";
                    else if (res == Constants.NERR_PasswordTooShort)
                        optionalStatusText = "ERROR: Password too short.";
                    else
                        optionalStatusText = $"ERROR: Password change failed with error: {res}";
                    optionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_ERROR;
                }
                else
                {
                    optionalStatusText = "Password changed.";
                    optionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_SUCCESS;
                }

                cpgsr = _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_FINISHED;
                cpcs = new _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION();
            }

            Logger.Write("Returning S_OK");
        }

        public virtual void ReportResult(
            int status,
            int ntsSubstatus,
            out string optionalStatusText,
            out _CREDENTIAL_PROVIDER_STATUS_ICON optionalStatusIcon)
        {
            Logger.Write($"ntsStatus: {status}; ntsSubstatus: {ntsSubstatus}");

            optionalStatusText = "";
            optionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE;
        }

        public virtual void GetUserSid(out string sid)
        {
            sid = _sid;

            Logger.Write($"username: {Common.GetNameFromSid(sid)}");
        }
    }
}
