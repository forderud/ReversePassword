using CredProvider.Interop;

namespace ReversePassword
{
    public class CredentialDescriptor
    {
        public _CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR Descriptor { get; set; }
        public _CREDENTIAL_PROVIDER_FIELD_STATE Visibility { get; set; }
        public object Value { get; set; }
    }

    public class CredentialView
    {
        public const int FIELD_USERNAME = 1;
        public const int FIELD_PASSWORD = 2;
        public const int FIELD_NEW_PASSWORD = 3;

        public const string CPFG_LOGON_PASSWORD_GUID = "60624cfa-a477-47b1-8a8e-3a4a19981827";
        public const string CPFG_CREDENTIAL_PROVIDER_LOGO = "2d837775-f6cd-464e-a745-482fd0b47493";
        public const string CPFG_CREDENTIAL_PROVIDER_LABEL = "286bbff3-bad4-438f-b007-79b7267c3d48";

        public readonly _CREDENTIAL_PROVIDER_USAGE_SCENARIO Usage; // LOGON, UNLOCK_WORKSTATION, CHANGE_PASSWORD, CREDUI or PLAP
        public int FieldsCount { get { return _fields.Count; } }

        private readonly List<CredentialDescriptor> _fields = new List<CredentialDescriptor>();


        public CredentialView(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usage) 
        {
            Usage = usage;

            if (!IsSupportedScenario(usage))
                return;

            var userNameState = (usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CREDUI) ?
                    _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE : _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;
            var confirmPasswordState = (usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD) ?
                    _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH : _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_HIDDEN;
            uint lastPwdField = (usage == _CREDENTIAL_PROVIDER_USAGE_SCENARIO.CPUS_CHANGE_PASSWORD) ? (uint)FIELD_NEW_PASSWORD : (uint)FIELD_PASSWORD;

            // icon
            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_TILE_IMAGE,
                label: "Icon",
                visibility: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH,
                value: null
            );
            // FIELD_USERNAME
            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_EDIT_TEXT,
                label: "Username",
                visibility: userNameState,
                value: null
            );
            // FIELD_PASSWORD
            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_PASSWORD_TEXT,
                label: "Password",
                visibility: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE,
                value: null
            );
            // FIELD_NEW_PASSWORD
            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_PASSWORD_TEXT,
                label: "New password",
                visibility: confirmPasswordState,
                value: null
            );
            // submit button
            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_SUBMIT_BUTTON,
                label: "Submit",
                visibility: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_SELECTED_TILE,
                value: lastPwdField // adjacentTo fieldID
            );
            // text label
            AddField(
                cpft: _CREDENTIAL_PROVIDER_FIELD_TYPE.CPFT_LARGE_TEXT,
                label: null,
                visibility: _CREDENTIAL_PROVIDER_FIELD_STATE.CPFS_DISPLAY_IN_BOTH,
                value: "Reverse Password"
            );
        }

        private void AddField(
            _CREDENTIAL_PROVIDER_FIELD_TYPE cpft,
            string label,
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
                    guidFieldType = default(Guid)
                }
            });
        }

        private static bool IsSupportedScenario(_CREDENTIAL_PROVIDER_USAGE_SCENARIO usage)
        {
            switch (usage)
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
    }
}
