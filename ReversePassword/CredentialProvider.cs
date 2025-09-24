using CredProvider.Interop;
using System.Runtime.InteropServices;
using static ReversePassword.Constants;

namespace ReversePassword
{
    [ComVisible(true)]
    [Guid(Constants.CredentialProvider_CLSID)]
    [ClassInterface(ClassInterfaceType.None)]
    [ProgId("ReversePassword")]
    public class CredentialProvider : ICredentialProvider, ICredentialProviderSetUserArray
    {
        private ICredentialProviderEvents _events;

        private CredentialView _view;
        private _CREDENTIAL_PROVIDER_USAGE_SCENARIO _usage;

        private List<ICredentialProviderUser> _providerUsers;

        public static CredentialView NotActive;

        protected CredentialView Initialize(_CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, uint flags)
        {
            var flags = (CredentialFlag)flags;

            Logger.Write($"cpus: {cpus}; dwFlags: {flags}");

            var isSupported = IsSupportedScenario(cpus);

            if (!isSupported)
            {
                if (NotActive == null) NotActive = new CredentialView(this) { Active = false };
                return NotActive;
            }

            var view = new CredentialView(this) { Active = true };
            var userNameState = (cpus == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CREDUI) ?
                    _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE : _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;
            var confirmPasswordState = (cpus == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD) ?
                    _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH : _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;

            view.AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_TILE_IMAGE,
                pszLabel: "Icon",
                state: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH,
                guidFieldType: Guid.Parse(CredentialView.CPFG_CREDENTIAL_PROVIDER_LOGO)
            );

            view.AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_EDIT_TEXT,
                pszLabel: "Username",
                state: userNameState
            );

            view.AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_PASSWORD_TEXT,
                pszLabel: "Password",
                state: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE,
                guidFieldType: Guid.Parse(CredentialView.CPFG_LOGON_PASSWORD_GUID)
            );

            view.AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_PASSWORD_TEXT,
                pszLabel: "Confirm password",
                state: confirmPasswordState,
                guidFieldType: Guid.Parse(CredentialView.CPFG_LOGON_PASSWORD_GUID)
            );

            view.AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_LARGE_TEXT,
                pszLabel: "Click Me!",
                defaultValue: "Reverse Password",
                state: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_DESELECTED_TILE
            );

            return view;
        }

        private static bool IsSupportedScenario(_CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
        {
            switch (cpus)
            {
                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CREDUI:
                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_UNLOCK_WORKSTATION:
                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_LOGON:
                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD:
                    return true;

                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_PLAP:
                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_INVALID:
                default:
                    return false;
            }
        }

        public virtual void SetUsageScenario(_CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, uint flags)
        {
            _view = Initialize(cpus, flags);
            _usage = cpus;

            if (_view.Active)
            {
                return;
            }

            throw new NotImplementedException();
        }

        public virtual void SetSerialization(ref _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION pcpcs)
        {
            Logger.Write($"ulAuthenticationPackage: {pcpcs.ulAuthenticationPackage}");
        }

        public virtual void Advise(ICredentialProviderEvents pcpe, ulong upAdviseContext)
        {
            Logger.Write($"upAdviseContext: {upAdviseContext}");

            if (pcpe != null)
            {
                _events = pcpe;
            }
        }

        public virtual void UnAdvise()
        {
            Logger.Write();

            if (_events != null)
            {
                _events = null;

                // release references to the host
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        public virtual void GetFieldDescriptorCount(out uint pdwCount)
        {
            pdwCount = (uint)_view.DescriptorCount;

            Logger.Write($"Returning field count: {pdwCount}");
        }

        public virtual void GetFieldDescriptorAt(uint idx, [Out] IntPtr ppcpfd)
        {
            if (_view.GetField((int)idx, ppcpfd))
            {
                return;
            }

            throw new ArgumentException();
        }

        public virtual void GetCredentialCount(
            out uint pdwCount,
            out uint pdwDefault,
            out int pbAutoLogonWithDefault
        )
        {
            pdwCount = (uint)_providerUsers.Count;

            pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;

            pbAutoLogonWithDefault = 0;

            Logger.Write($"pdwCount={pdwCount} pdwDefault={pdwDefault}");
        }

        public virtual void GetCredentialAt(uint idx, out ICredentialProviderCredential ppcpc)
        {
            Logger.Write($"dwIndex: {idx}");

            ppcpc = _view.GetCredential((int)idx);
        }

        public virtual _CREDENTIAL_PROVIDER_USAGE_SCENARIO GetUsage()
        {
            return _usage;
        }

        public virtual void SetUserArray(ICredentialProviderUserArray users)
        {
            _providerUsers = new List<ICredentialProviderUser>();

            users.GetCount(out uint count);
            users.GetAccountOptions(out CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS options);

            Logger.Write($"count: {count}; options: {options}");

            for (uint i = 0; i < count; i++)
            {
                users.GetAt(i, out ICredentialProviderUser user);

                user.GetProviderID(out Guid providerId);
                user.GetSid(out string sid);

                _providerUsers.Add(user);

                Logger.Write($"providerId: {providerId}; username: {Common.GetNameFromSid(sid)}");
            }
        }

        //Lookup the user by index and return the sid
        public string GetUserSidInternal(int idx)
        {
            //CredUI does not provide user sids, so return null
            if (_providerUsers.Count < idx + 1)
                return null;

            _providerUsers[idx].GetSid(out string sid);
            return sid;
        }
    }
}
