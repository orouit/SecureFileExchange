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
    /// <summary>
    /// Implements the IEncryptor interface for an RSA AOEP asymetric algorithm
    /// </summary>
    [Serializable]
    public class RSAOAEPEncryptor : RSABase, IDigestEncryptor
    {
        public RSAOAEPEncryptor(RSACryptoServiceProvider rsaCryptoProvider)
            : base(rsaCryptoProvider, rsaCryptoProvider.KeyExchangeAlgorithm, "SHA1")
        {
        }

        public RSAOAEPEncryptor(DigestData digestData, RSACryptoServiceProvider rsaCryptoProvider)
            : base(digestData, rsaCryptoProvider)
        {
        }

        public void Encrypt(byte[] data)
        {
            byte[] encrypted = rsaCryptoProvider.Encrypt(data, true);
            digest = Convert.ToBase64String(encrypted);
        }

        public byte[] Decrypt()
        {
            byte[] encrypted = Convert.FromBase64String(digest);

            return rsaCryptoProvider.Decrypt(encrypted, true);
        }

        [JsonIgnore]
        DigestData IDigestEncryptor.Digest
        {
            get { return this; }
        }
    }
}
