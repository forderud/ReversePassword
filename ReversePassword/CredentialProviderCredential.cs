﻿using CredProvider.Interop;
using System.Drawing;
using System.Reflection;
using System.Runtime.InteropServices;
using static ReversePassword.Constants;

namespace ReversePassword
{
    public class CredentialProviderCredential : ICredentialProviderCredential2
    {
        private readonly CredentialView view;
        private readonly string sid;

        public CredentialProviderCredential(CredentialView view, string sid)
        {
            Logger.Write($"username={Common.GetNameFromSid(sid)}");

            this.view = view;
            this.sid = sid;
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
            uint dwFieldID,
            out _CREDENTIAL_PROVIDER_FIELD_STATE pcpfs,
            out _CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE pcpfis
        )
        {
            Logger.Write($"dwFieldID: {dwFieldID}");

            view.GetFieldState((int)dwFieldID, out pcpfs, out pcpfis);
        }

        public virtual void GetStringValue(uint dwFieldID, out string ppsz)
        {
            ppsz = view.GetValue((int)dwFieldID);
            Logger.Write($"dwFieldID:{dwFieldID}, ppsz={ppsz}");
        }

        private Bitmap tileIcon;

        public virtual void GetBitmapValue(uint dwFieldID, out IntPtr phbmp)
        {
            Logger.Write($"dwFieldID: {dwFieldID}");

            try
            {
                TryLoadUserIcon();
            }
            catch (Exception ex) 
            {
                Logger.Write("Error: " + ex);
            }

            phbmp = tileIcon?.GetHbitmap() ?? IntPtr.Zero;
        }

        private void TryLoadUserIcon()
        {
            if (tileIcon == null)
            {
                var fileName = "ReversePassword.tile-icon.bmp";
                var assembly = Assembly.GetExecutingAssembly();
                var stream = assembly.GetManifestResourceStream(fileName);

                tileIcon = (Bitmap)Image.FromStream(stream);
            }
        }

        public virtual void GetCheckboxValue(uint dwFieldID, out int pbChecked, out string ppszLabel)
        {
            Logger.Write($"dwFieldID: {dwFieldID}");

            pbChecked = 0;
            ppszLabel = "";

            throw new NotImplementedException();
        }

        public virtual void GetSubmitButtonValue(uint dwFieldID, out uint pdwAdjacentTo)
        {
            Logger.Write($"dwFieldID: {dwFieldID}");

            pdwAdjacentTo = 0;

            throw new NotImplementedException();
        }

        public virtual void GetComboBoxValueCount(uint dwFieldID, out uint pcItems, out uint pdwSelectedItem)
        {
            Logger.Write($"dwFieldID: {dwFieldID}");

            pcItems = 0;
            pdwSelectedItem = 0;

            throw new NotImplementedException();
        }

        public virtual void GetComboBoxValueAt(uint dwFieldID, uint dwItem, out string ppszItem)
        {
            Logger.Write($"dwFieldID: {dwFieldID}; dwItem: {dwItem}");

            ppszItem = "";

            throw new NotImplementedException();
        }

        public virtual void SetStringValue(uint dwFieldID, string psz)
        {
            Logger.Write($"dwFieldID: {dwFieldID}; psz: {psz}");

            view.SetValue((int) dwFieldID, psz);
        }

        public virtual void SetCheckboxValue(uint dwFieldID, int bChecked)
        {
            Logger.Write($"dwFieldID: {dwFieldID}; bChecked: {bChecked}");

            throw new NotImplementedException();
        }

        public virtual void SetComboBoxSelectedValue(uint dwFieldID, uint dwSelectedItem)
        {
            Logger.Write($"dwFieldID: {dwFieldID}; dwSelectedItem: {dwSelectedItem}");

            throw new NotImplementedException();
        }

        public virtual void CommandLinkClicked(uint dwFieldID)
        {
            Logger.Write($"dwFieldID: {dwFieldID}");

            throw new NotImplementedException();
        }

        public virtual void GetSerialization(
            out _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE pcpgsr,
            out _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION pcpcs,
            out string ppszOptionalStatusText,
            out _CREDENTIAL_PROVIDER_STATUS_ICON pcpsiOptionalStatusIcon
        )
        {
            Logger.Write();

            var usage = this.view.Provider.GetUsage();

            pcpgsr = _CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE.CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            pcpcs = new _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION();
            ppszOptionalStatusText = "";
            pcpsiOptionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE;

            //Serialization can be called before the user has entered any values. Only applies to logon usage scenarios
            if (usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_LOGON || usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_UNLOCK_WORKSTATION)
            {
                //Determine the authentication package
                Common.RetrieveNegotiateAuthPackage(out var authPackage);

                //Only credential packing for msv1_0 is supported using this code
                Logger.Write($"Got authentication package: {authPackage}. Only local authenticsation package 0 (msv1_0) is supported.");

                //Get username and password
                var username = Common.GetNameFromSid(this.sid);
                GetStringValue(2, out var password);

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

                //This should work fine in Windows 10 that only uses the Logon scenario
                //But it could fail for the workstation unlock scanario on older OS's
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
            //Implement code to change password here. This is not handled natively.
            else if (usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD)
            {
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
            out _CREDENTIAL_PROVIDER_STATUS_ICON pcpsiOptionalStatusIcon
        )
        {
            Logger.Write($"ntsStatus: {ntsStatus}; ntsSubstatus: {ntsSubstatus}");

            ppszOptionalStatusText = "";
            pcpsiOptionalStatusIcon = _CREDENTIAL_PROVIDER_STATUS_ICON.CPSI_NONE;
        }

        public virtual void GetUserSid(out string sid)
        {
            sid = this.sid;

            Logger.Write($"username: {Common.GetNameFromSid(sid)}");
        }
    }
}