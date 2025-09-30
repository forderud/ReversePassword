using CredProvider.Interop;

namespace ReversePassword
{
    /** Minimal _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_COMBOBOX implementation. */
    public class ComboBox
    {
        public uint selectedItem = 0;
        public List<string> items = new List<string>();
    }

    public class CredentialDescriptor
    {
        public _CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR Descriptor { get; set; }
        public _CREDENTIAL_PROVIDER_FIELD_STATE Visibility { get; set; }
        public object Value { get; set; }
    }

    public class CredentialView
    {
        public const string CPFG_LOGON_PASSWORD_GUID = "60624cfa-a477-47b1-8a8e-3a4a19981827";
        public const string CPFG_CREDENTIAL_PROVIDER_LOGO = "2d837775-f6cd-464e-a745-482fd0b47493";
        public const string CPFG_CREDENTIAL_PROVIDER_LABEL = "286bbff3-bad4-438f-b007-79b7267c3d48";

        public readonly _CREDENTIAL_PROVIDER_USAGE_SCENARIO Usage; // LOGON, UNLOCK_WORKSTATION, CHANGE_PASSWORD, CREDUI or PLAP
        public int FieldsCount { get { return _fields.Count; } }

        private readonly List<CredentialDescriptor> _fields = new List<CredentialDescriptor>();
        private readonly Dictionary<string, ICredentialProviderCredential> _credentials = new Dictionary<string, ICredentialProviderCredential>(); // sid as key


        public CredentialView(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usage) 
        {
            Usage = usage;
        }

        public void AddField(
            _CREDENTIAL_PROVIDER_FIELD_TYPE cpft,
            string label,
            Guid guidFieldType,
            _CREDENTIAL_PROVIDER_FIELD_STATE visibility,
            object value)
        {
            _fields.Add(new CredentialDescriptor
            {
                Visibility = visibility,
                Value = value,
                Descriptor = new _CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR
                {
                    dwFieldID = (uint)_fields.Count,
                    cpft = cpft,
                    pszLabel = label,
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

        public ICredentialProviderCredential GetCredential(string sid)
        {
            // cache lookup
            if (_credentials.TryGetValue(sid, out ICredentialProviderCredential credential))
            {
                Logger.Write("Returning existing credential.");
                return credential;
            }

            // add credential to dict
            credential = new CredentialProviderCredential(this, sid);
            _credentials[sid] = credential;

            Logger.Write($"Returning new credential for username={Common.GetNameFromSid(sid)}");
            return credential;
        }
    }
}
