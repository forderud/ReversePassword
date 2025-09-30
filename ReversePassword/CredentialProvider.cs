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

        public virtual void SetUsageScenario(_CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, uint flags_)
        {
            var flags = (CredentialFlag)flags_;
            Logger.Write($"cpus: {cpus}; dwFlags: {flags}");

            _view = new CredentialView(cpus);

            if (_view.FieldsCount == 0)
            {
                Logger.Write("throw new NotSupportedException");
                throw new NotSupportedException();
            }

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
            {
                Logger.Write("throw new ArgumentException");
                throw new ArgumentException();
            }

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
            {
                Logger.Write("throw new ArgumentException");
                throw new ArgumentException();
            }

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
