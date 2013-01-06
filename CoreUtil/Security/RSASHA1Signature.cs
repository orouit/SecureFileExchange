/**
 * CodeProject license
 */

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Core.Security
{
    [Serializable]
    public class RSASHA1Signature : RSABase, IDigestSignature
    {
        public RSASHA1Signature(RSACryptoServiceProvider rsaCryptoProvider)
            : base(rsaCryptoProvider, rsaCryptoProvider.SignatureAlgorithm, "SHA1")
        {
        }

        public RSASHA1Signature(DigestData digestData, RSACryptoServiceProvider rsaCryptoProvider)
            : base(digestData, rsaCryptoProvider)
        {
        }

        void IDigestSignature.Sign(byte[] dataToSign)
        {
            byte[] signature = rsaCryptoProvider.SignData(dataToSign, new SHA1Managed());
            digest = Convert.ToBase64String(signature);
        }

        bool IDigestSignature.Verify(byte[] dataToVerify)
        {
            byte[] signature = Convert.FromBase64String(digest);

            return rsaCryptoProvider.VerifyData(dataToVerify, new SHA1Managed(), signature);
        }

        [JsonIgnore]
        DigestData IDigestSignature.Digest
        {
            get { return this; }
        }
    }
}
