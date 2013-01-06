/**
 * CodeProject license
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Core.Security
{
    [Serializable]
    public abstract class RSABase : DigestData
    {
        [JsonIgnore]
        protected RSACryptoServiceProvider rsaCryptoProvider;

        protected RSABase(RSACryptoServiceProvider rsaCryptoProvider, string algorithm, string hash)
            : base(algorithm, hash)
        {
            this.rsaCryptoProvider = rsaCryptoProvider;
        }

        protected RSABase(DigestData digestData, RSACryptoServiceProvider rsaCryptoProvider)
            : base(digestData.Algorithm, digestData.Hash)
        {
            this.rsaCryptoProvider = rsaCryptoProvider;
            this.digest = digestData.Digest;
        }
    }
}
