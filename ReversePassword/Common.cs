using System.Security.Principal;

namespace ReversePassword
{
    static class Common
    {
        //Determine authentication package required
        public static uint RetrieveNegotiateAuthPackage(out uint authPackage)
        {
            Logger.Write();

            // establish LSA connection
            var status = PInvoke.LsaConnectUntrusted(out var lsaHandle);

            // use NoPasswordAuthPkg if installed
            using (var name = new PInvoke.LsaStringWrapper("NoPasswordAuthPkg"))
            {
                status = PInvoke.LsaLookupAuthenticationPackage(lsaHandle, ref name._string, out authPackage);
            }
            if (status != Constants.STATUS_SUCCESS)
            {
                // falback to Negotiate that allows LSA to decide whether to use MSV1_0 or Kerberos
                using (var name = new PInvoke.LsaStringWrapper("Negotiate"))
                {
                    status = PInvoke.LsaLookupAuthenticationPackage(lsaHandle, ref name._string, out authPackage);
                }
            }

            // close LSA handle
            PInvoke.LsaDeregisterLogonProcess(lsaHandle);

            return status;
        }

        public static string GetNameFromSid(string value)
        {
            var sid = new SecurityIdentifier(value);
            var ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));

            return ntAccount.ToString();
        }
    }
}
