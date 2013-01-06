/**
 * CodeProject license
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Reflection;

namespace Core.Security
{
    /// <summary>
    /// This class is used to create a typed DigestData object given one that was reconstructed
    /// from a Json serialization
    /// </summary>
    public static class RSADigestFactory
    {
        static RSADigestFactory()
        {
            CreateRSADigestTypeDictionary();
        }

        const string 
            RSAOAEPAlgo = "RSA-PKCS1-KeyEx",
            RSASignatureAlgo = "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            SHA1 = "SHA1";

        private static Dictionary<string, Type> typePerAlgo = new Dictionary<string, Type>();

        public static DigestData CreateDigestData(DigestData digest, RSACryptoServiceProvider rsaCryptoProvider)
        {
            DigestData digestData = null;
            Type digestDataType = null;

            if (typePerAlgo.TryGetValue(GetAlgoHash(digest.Algorithm, digest.Hash), out digestDataType))
            {
                ConstructorInfo digestCstr = digestDataType.GetConstructor(new Type[] { typeof(DigestData), typeof(RSACryptoServiceProvider) });
                if (digestCstr != null)
                {
                    digestData = digestCstr.Invoke(new object[] { digest, rsaCryptoProvider }) as DigestData;
                }
            }

            return digestData;
        }

        private static void CreateRSADigestTypeDictionary()
        {
            // RSAAOEPEncrytor
            typePerAlgo.Add(GetRSAOAEPAlgoHash(), typeof(RSAOAEPEncryptor));

            // RSASHA1Signature
            typePerAlgo.Add(GetRSASignatureAlgoHash(), typeof(RSASHA1Signature));
        }

        private static string GetRSAOAEPAlgoHash()
        {
            return GetAlgoHash(RSAOAEPAlgo, SHA1);
        }

        private static string GetRSASignatureAlgoHash()
        {
            return GetAlgoHash(RSASignatureAlgo, SHA1);
        }

        private static string GetAlgoHash(string algoName, string hashName)
        {
            SHA1Managed sha1 = new SHA1Managed();
            StringBuilder algoHash = new StringBuilder(algoName);
            algoHash.Append(hashName);

            return Convert.ToBase64String(sha1.ComputeHash(ASCIIEncoding.ASCII.GetBytes(algoHash.ToString())));
        }
    }
}
