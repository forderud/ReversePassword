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
        private List<ICredentialProviderUser> _users;

        private CredentialView Initialize(_CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, CredentialFlag flags)
        {
            if (!IsSupportedScenario(cpus))
                return new CredentialView(/*Active*/false, cpus);

            var view = new CredentialView(/*Active*/true, cpus);
            var userNameState = (cpus == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CREDUI) ?
                    _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE : _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;
            var confirmPasswordState = (cpus == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD) ?
                    _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH : _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;

            view.AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_TILE_IMAGE,
                label: "Icon",
                guidFieldType: default(Guid),
                visibility: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH, // display in selected & deselected tiles
                value: null
            );

            view.AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_EDIT_TEXT,
                label: "Username",
                guidFieldType: default(Guid),
                visibility: userNameState,
                value: null
            );

            view.AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_PASSWORD_TEXT,
                label: "Password",
                guidFieldType: default(Guid),
                visibility: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE,
                value: null
            );

            view.AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_PASSWORD_TEXT,
                label: "New password",
                guidFieldType: default(Guid),
                visibility: confirmPasswordState,
                value: null
            );

            view.AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_LARGE_TEXT,
                label: null,
                guidFieldType: default(Guid),
                visibility: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH,
                value: "Reverse Password"
            );

            return view;
        }

        private static bool IsSupportedScenario(_CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
        {
            switch (cpus)
            {
                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_LOGON:
                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_UNLOCK_WORKSTATION:
                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD:
                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CREDUI:
                    return true;

                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_INVALID:
                case _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_PLAP:
                default:
                    return false;
            }
        }

        public virtual void SetUsageScenario(_CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, uint flags_)
        {
            var flags = (CredentialFlag)flags_;
            Logger.Write($"cpus: {cpus}; dwFlags: {flags}");

            _view = Initialize(cpus, flags);

            if (!_view.Active)
                throw new NotSupportedException();

            return;
        }

        public virtual void SetSerialization(ref _CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION cpcs)
        {
            Logger.Write($"ulAuthenticationPackage: {cpcs.ulAuthenticationPackage}");
        }

        public virtual void Advise(ICredentialProviderEvents cpe, ulong adviseContext)
        {
            Logger.Write($"upAdviseContext: {adviseContext}");

            if (cpe != null)
            {
                _events = cpe;
            }
        }

        public virtual void UnAdvise()
        {
            Logger.Write();

            if (_events != null)
            {
                _events = null;

                // release references
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        public virtual void GetFieldDescriptorCount(out uint count)
        {
            count = (uint)_view.FieldsCount;

            Logger.Write($"Returning field count: {count}");
        }

        public virtual void GetFieldDescriptorAt(uint idx, [Out] IntPtr cpfd)
        {
            Logger.Write($"idx: {idx}");

            CredentialDescriptor field = _view.GetField(idx);
            if (field == null)
                throw new ArgumentException();

            var pcpfd = Marshal.AllocHGlobal(Marshal.SizeOf(field.Descriptor));
            Marshal.StructureToPtr(field.Descriptor, pcpfd, false); // copy field descriptor content
            Marshal.StructureToPtr(pcpfd, cpfd, false); // copy pointer to field descriptor
        }

        public virtual void GetCredentialCount(
            out uint count,
            out uint default_idx,
            out int autoLogonWithDefault)
        {
            count = (uint)_users.Count;

            default_idx = CREDENTIAL_PROVIDER_NO_DEFAULT;

            autoLogonWithDefault = 0;

            Logger.Write($"pdwCount: {count} pdwDefault: {default_idx}");
        }

        public virtual void GetCredentialAt(uint idx, out ICredentialProviderCredential cpc)
        {
            Logger.Write($"dwIndex: {idx}");

            if (idx >= _users.Count)
                throw new ArgumentException();

            _users[(int)idx].GetSid(out string sid);

            cpc = _view.GetCredential(sid);
        }

        public virtual void SetUserArray(ICredentialProviderUserArray users)
        {
            _users = new List<ICredentialProviderUser>();

            users.GetCount(out uint count);
            users.GetAccountOptions(out CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS options);

            Logger.Write($"count: {count}; options: {options}");

            for (uint i = 0; i < count; i++)
            {
                users.GetAt(i, out ICredentialProviderUser user);

                user.GetProviderID(out Guid providerId);
                user.GetSid(out string sid);

                _users.Add(user);

                Logger.Write($"providerId: {providerId}; username: {Common.GetNameFromSid(sid)}");
            }
        }
    }
}
