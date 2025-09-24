using CredProvider.Interop;

namespace ReversePassword
{
    public class CredentialDescriptor
    {
        public _CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR Descriptor { get; set; }
        public _CREDENTIAL_PROVIDER_FIELD_STATE State { get; set; }
        public object Value { get; set; }
    }

    public class CredentialView
    {
        public const string CPFG_LOGON_PASSWORD_GUID = "60624cfa-a477-47b1-8a8e-3a4a19981827";
        public const string CPFG_CREDENTIAL_PROVIDER_LOGO = "2d837775-f6cd-464e-a745-482fd0b47493";
        public const string CPFG_CREDENTIAL_PROVIDER_LABEL = "286bbff3-bad4-438f-b007-79b7267c3d48";

        private readonly List<CredentialDescriptor> _fields = new List<CredentialDescriptor>();

        public CredentialProvider Provider { get; private set; }

        public bool Active { get; set; }

        public int DescriptorCount { get { return _fields.Count; } }

        private readonly Dictionary<int, ICredentialProviderCredential> _credentials = new Dictionary<int, ICredentialProviderCredential>();


        public CredentialView(CredentialProvider provider) 
        {
            Provider = provider;
        }

        public void AddField(
            _CREDENTIAL_PROVIDER_FIELD_TYPE cpft,
            string pszLabel,
            _CREDENTIAL_PROVIDER_FIELD_STATE state,
            string defaultValue = null,
            Guid guidFieldType = default(Guid))
        {
            if (!Active)
                throw new NotSupportedException();

            _fields.Add(new CredentialDescriptor
            {
                State = state,
                Value = defaultValue,
                Descriptor = new _CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR
                {
                    dwFieldID = (uint)_fields.Count,
                    cpft = cpft,
                    pszLabel = pszLabel,
                    guidFieldType = guidFieldType
                }
            });
        }

        public CredentialDescriptor GetField(uint idx)
        {
            if (idx >= _fields.Count)
                return null;

            return _fields[(int)idx];
        }

        public ICredentialProviderCredential GetCredential(uint idx)
        {
            // cache lookup
            if (_credentials.TryGetValue((int)idx, out ICredentialProviderCredential credential))
            {
                Logger.Write("Returning existing credential.");
                return credential;
            }

            // add credential to dict
            var sid = Provider.GetUserSidInternal(idx);
            credential = new CredentialProviderCredential(this, sid);
            _credentials[(int)idx] = credential;

            Logger.Write($"Returning new credential for username={Common.GetNameFromSid(sid)}");
            return credential;
        }
    }
}
