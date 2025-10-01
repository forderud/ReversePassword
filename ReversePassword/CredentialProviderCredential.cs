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
            if (cpce is ICredentialProviderCredentialEvents2 ev2)
                Logger.Write("pcpce is ICredentialProviderCredentialEvents2");

            Logger.Write("throw new NotImplementedException");
            throw new NotImplementedException();
        }

        public virtual void UnAdvise()
        {
            Logger.Write("throw new NotImplementedException");
            throw new NotImplementedException();
        }

        public virtual void SetSelected(out int autoLogon)
        {
            //Set this to 1 if you would like GetSerialization called immediately on selection
            autoLogon = 0;
            Logger.Write($"Returning autoLogon: {autoLogon}");
        }

        public virtual void SetDeselected()
        {
            Logger.Write();
            // purge buffers containing sensitive information
        }

        public virtual void GetFieldState(
            uint fieldID,
            out _CREDENTIAL_PROVIDER_FIELD_STATE cpfs,
            out _CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            CredentialDescriptor field = _view.GetField(fieldID);

            cpfs = field.Visibility;
            cpfis = _CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE.CPFIS_NONE; // NONE, READONLY, DISABLED or FOCUSED
            Logger.Write($"Returning field state: {cpfs}, interactiveState: {cpfis}");
        }

        public virtual void GetStringValue(uint fieldID, out string val)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            // Valid for CPFT_LARGE_TEXT, CPFT_SMALL_TEXT, CPFT_COMMAND_LINK, CPFT_EDIT_TEXT & CPFT_PASSWORD_TEXT
            CredentialDescriptor desc = _view.GetField(fieldID);
            if ((desc.Descriptor.cpft < _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_LARGE_TEXT) || (desc.Descriptor.cpft > _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_PASSWORD_TEXT))
            {
                Logger.Write("throw new InvalidCastException");
                throw new InvalidCastException();
            }

            val = (string)desc.Value;
            Logger.Write($"Returning ppsz: {val}");
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

            CredentialDescriptor desc = _view.GetField(fieldID);
            isChecked = (int)desc.Value; // bool value
            label = desc.Descriptor.pszLabel;
            Logger.Write($"Returning isChecked: {isChecked}, label: {label}");
        }

        public virtual void GetSubmitButtonValue(uint fieldID, out uint adjacentTo)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            CredentialDescriptor desc = _view.GetField(fieldID);
            if (desc.Descriptor.cpft != _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_SUBMIT_BUTTON)
            {
                Logger.Write("throw new InvalidCastException");
                throw new InvalidCastException();
            }

            adjacentTo = (uint)desc.Value; // assume value contains adjacentTo fieldID
            Logger.Write($"Returning adjacentTo: {adjacentTo}");
        }

        public virtual void GetComboBoxValueCount(uint fieldID, out uint itemCount, out uint selectedItem)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            CredentialDescriptor desc = _view.GetField(fieldID);
            if (desc.Descriptor.cpft != _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_COMBOBOX)
            {
                Logger.Write("throw new InvalidCastException");
                throw new InvalidCastException();
            }

            var cb = desc.Value as ComboBox;
            itemCount = (uint)cb.items.Count;
            selectedItem = cb.selectedItem;
            Logger.Write($"Returning itemCount: {itemCount}, selectedItem: {selectedItem}");
        }

        public virtual void GetComboBoxValueAt(uint fieldID, uint item, out string val)
        {
            Logger.Write($"dwFieldID: {fieldID}; dwItem: {item}");

            CredentialDescriptor desc = _view.GetField(fieldID);
            if (desc.Descriptor.cpft != _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_COMBOBOX)
            {
                Logger.Write("throw new InvalidCastException");
                throw new InvalidCastException();
            }

            var cb = desc.Value as ComboBox;
            val = cb.items[(int)item];
            Logger.Write($"Returning val: {val}");
        }

        public virtual void SetStringValue(uint fieldID, string val)
        {
            Logger.Write($"dwFieldID: {fieldID}; psz: {val}");

            // valid for CPFT_EDIT_TEXT & CPFT_PASSWORD_TEXT
            CredentialDescriptor desc = _view.GetField(fieldID);
            if ((desc.Descriptor.cpft != _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_EDIT_TEXT) && (desc.Descriptor.cpft != _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_PASSWORD_TEXT))
            {
                Logger.Write("throw new InvalidCastException");
                throw new InvalidCastException();
            }

            desc.Value = val;
            Logger.Write($"Returning");
        }

        public virtual void SetCheckboxValue(uint fieldID, int isChecked)
        {
            Logger.Write($"dwFieldID: {fieldID}; bChecked: {isChecked}");

            CredentialDescriptor desc = _view.GetField(fieldID);
            desc.Value = isChecked;
            Logger.Write($"Returning");
        }

        public virtual void SetComboBoxSelectedValue(uint fieldID, uint selectedItem)
        {
            Logger.Write($"dwFieldID: {fieldID}; dwSelectedItem: {selectedItem}");

            CredentialDescriptor desc = _view.GetField(fieldID);
            if (desc.Descriptor.cpft != _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_COMBOBOX)
            {
                Logger.Write("throw new InvalidCastException");
                throw new InvalidCastException();
            }

            var cb = desc.Value as ComboBox;
            cb.selectedItem = selectedItem;
            Logger.Write($"Returning");
        }

        public virtual void CommandLinkClicked(uint fieldID)
        {
            Logger.Write($"dwFieldID: {fieldID}");

            CredentialDescriptor desc = _view.GetField(fieldID);
            if (desc.Descriptor.cpft != _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_COMMAND_LINK)
            {
                Logger.Write("throw new InvalidCastException");
                throw new InvalidCastException();
            }

            string url = (string)desc.Value;
            // TODO: Open URL in some way
            Logger.Write("throw new NotImplementedException");
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
                string username;
                if (usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CREDUI)
                    username = (string)_view.GetField(1).Value; // user-entered
                else
                    username = Common.GetNameFromSid(_sid); // implicit

                var password = (string)_view.GetField(2).Value;
                password = Reverse(password);

                Logger.Write($"Preparing to serialise credential with username: {username} and password: {password}");
                cpgsr = _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_RETURN_CREDENTIAL_FINISHED;

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
                string username = Common.GetNameFromSid(_sid); // in <domain>\<user> format
                string oldPwd = (string)_view.GetField(2).Value;
                oldPwd = Reverse(oldPwd);
                string newPwd = (string)_view.GetField(3).Value;
                newPwd = Reverse(newPwd);

                string[] domainUser = username.Split('\\');
                Logger.Write($"Changing password for domain: {domainUser[0]}, username: {domainUser[1]}");

                uint res = PInvoke.NetUserChangePassword(domainUser[0], domainUser[1], oldPwd, newPwd);
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
            }

            Logger.Write("Returning S_OK");
        }

        public virtual void ReportResult(
            int status,
            int ntsSubstatus,
            out string optionalStatusText,
            out _CREDENTIAL_PROVIDER_STATUS_ICON optionalStatusIcon)
        {
            Logger.Write($"ntsStatus: 0x{status:X}; ntsSubstatus: 0x{ntsSubstatus:X}");

            optionalStatusText = "";
            optionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE;
        }

        public virtual void GetUserSid(out string sid)
        {
            sid = _sid;

            Logger.Write($"username: {Common.GetNameFromSid(sid)}");
        }

        private static string Reverse (string text)
        {
            char[] charArray = text.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }
    }
}
