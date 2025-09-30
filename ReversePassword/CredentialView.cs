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


        public CredentialView(_CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus) 
        {
            Usage = cpus;

            if (!IsSupportedScenario(cpus))
                return;

            var userNameState = (cpus == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CREDUI) ?
                    _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE : _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;
            var confirmPasswordState = (cpus == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD) ?
                    _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH : _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;
            uint lastPwdField = (cpus == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD) ? (uint)3 : (uint)2;

            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_TILE_IMAGE,
                label: "Icon",
                guidFieldType: default(Guid),
                visibility: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH,
                value: null
            );

            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_EDIT_TEXT,
                label: "Username",
                guidFieldType: default(Guid),
                visibility: userNameState,
                value: null
            );

            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_PASSWORD_TEXT,
                label: "Password",
                guidFieldType: default(Guid),
                visibility: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE,
                value: null
            );

            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_PASSWORD_TEXT,
                label: "New password",
                guidFieldType: default(Guid),
                visibility: confirmPasswordState,
                value: null
            );

            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_SUBMIT_BUTTON,
                label: "Submit",
                guidFieldType: default(Guid),
                visibility: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE,
                value: lastPwdField // adjacentTo fieldID
            );

            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_LARGE_TEXT,
                label: null,
                guidFieldType: default(Guid),
                visibility: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH,
                value: "Reverse Password"
            );
        }

        private void AddField(
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
