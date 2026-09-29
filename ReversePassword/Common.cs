using System.Security.Principal;

namespace ReversePassword
{
    static class Common
    {
        public static uint GetAuthenticationPackage(out uint authPackage)
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

        public static string GetAccountName(string sidStr)
        {
            var sid = new SecurityIdentifier(sidStr);
            var ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));

            return ntAccount.ToString();
        }
    }
}
