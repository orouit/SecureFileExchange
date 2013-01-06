/**
 * CodeProject license
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Core.Security
{
    /// <summary>
    /// This  class uses AES with a key of 256bits.
    /// Key and IV are computed from a text password using a SHA384 
    /// </summary>
    public class AESEncryptor : IEncryptProcess
    {
        private const int AESKeySize = 256;
        private AesCryptoServiceProvider aesProvider;
        private SHA384 sha384;
        private byte[] 
            AesKey = null,
            AesIV = null;

        #region Constructor

        /// <summary>
        /// Initialize the encryptor
        /// </summary>
        public AESEncryptor()
        {
            aesProvider = new AesCryptoServiceProvider();
            aesProvider.KeySize = AESKeySize;

            sha384 = SHA384.Create();
        }

        /// <summary>
        /// Initilizes the encryptor with a given password
        /// </summary>
        /// <param name="password">Password text</param>
        public AESEncryptor(string password)
            : this()
        {
            MakeKeyFromPassword(password);
        }

        /// <summary>
        /// Initialize the AESEncryptor object from the AES Key and IV that were decrypted
        /// </summary>
        /// <param name="aesKeyAndIV"></param>
        public AESEncryptor(byte[] aesKeyAndIV)
            : this()
        {
            AesKey = new byte[AESKeySize / 8];
            AesIV = new byte[(AESKeySize / 8) / 2];

            Buffer.BlockCopy(aesKeyAndIV, 0, AesKey, 0, AesKey.Length);
            Buffer.BlockCopy(aesKeyAndIV, AesKey.Length, AesIV, 0, AesIV.Length);

            aesProvider.Key = AesKey;
            aesProvider.IV = AesIV;
        }

        #endregion

        #region Public methods

        /// <summary>
        /// Generates a AES key and IV using a password
        /// </summary>
        /// <param name="password"></param>
        public void MakeKeyFromPassword(string password)
        {
            byte[] passbytes = ASCIIEncoding.ASCII.GetBytes(password);
            byte[] keyIV = sha384.ComputeHash(passbytes);

            int AESKeyByteLength = AESKeySize / 8;
            int AESIVByteLength = AESKeySize / 16;
            AesKey = new byte[AESKeyByteLength];
            AesIV = new byte[AESIVByteLength];

            Buffer.BlockCopy(keyIV, 0, AesKey, 0, AESKeyByteLength);
            Buffer.BlockCopy(keyIV, AESKeyByteLength, AesIV, 0, AESIVByteLength);

            aesProvider.Key = AesKey;
            aesProvider.IV = AesIV;
        }

        /// <summary>
        /// Encrypt a buffer of data
        /// </summary>
        /// <param name="dataToEncrypt">Data to encrypt</param>
        /// <returns>Encrypted data</returns>
        public byte[] EncryptData(byte[] dataToEncrypt)
        {
            if (AesKey == null || AesIV == null)
            {
                throw new ArgumentException("Call MakeKeyFromPassword to initialize the Keys");
            }

            //byte[] outputEncr = null;
            ICryptoTransform aesEncryptor = aesProvider.CreateEncryptor();
            //using (MemoryStream msEncrypt = new MemoryStream(dataToEncrypt))
            //{
            //    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aesEncryptor, CryptoStreamMode.Read))
            //    {
            //        using (MemoryStream msOutStream = new MemoryStream())
            //        {
            //            int blockSize = 64;
            //            int nbRead = 0;
            //            byte[] outputBlock = new byte[blockSize];
            //            do
            //            {
            //                nbRead = csEncrypt.Read(outputBlock, 0, blockSize);
            //                msOutStream.Write(outputBlock, 0, nbRead);
            //            }
            //            while (nbRead == blockSize);

            //            outputEncr = msOutStream.ToArray();
            //        }
            //    }
            //}            

            //return outputEncr;
            return ProcessCryptoStream(aesEncryptor, dataToEncrypt);
        }

        /// <summary>
        /// Decrypt a buffer of data
        /// </summary>
        /// <param name="dataToDecrypt">Data to decrypt</param>
        /// <returns>Decrypted data</returns>
        public byte[] DecryptData(byte[] dataToDecrypt)
        {
            if (AesKey == null || AesIV == null)
            {
                throw new ArgumentException("Call MakeKeyFromPassword to initialize the Keys");
            }

            //byte[] outputDecr = null;
            ICryptoTransform aesDecryptor = aesProvider.CreateDecryptor();
            //using (MemoryStream msDecrypt = new MemoryStream(dataToDecrypt))
            //{
            //    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, aesDecryptor, CryptoStreamMode.Read))
            //    {
            //        using (MemoryStream msOutStream = new MemoryStream())
            //        {
            //            int blockSize = 64;
            //            int nbRead = 0;
            //            byte[] outputBlock = new byte[blockSize];
            //            do
            //            {
            //                nbRead = csDecrypt.Read(outputBlock, 0, blockSize);
            //                msOutStream.Write(outputBlock, 0, nbRead);
            //            }
            //            while (nbRead == blockSize);

            //            outputDecr = msOutStream.ToArray();
            //        }
            //    }
            //}

            //return outputDecr;
            return ProcessCryptoStream(aesDecryptor, dataToDecrypt);
        }

        /// <summary>
        /// Encrypt a text and convert the encrypted data to base64.
        /// 
        /// Used to encrypt passwords
        /// </summary>
        /// <param name="toEncrypt">Text to encrypt</param>
        /// <returns>Encrypted text, base64 encoded</returns>
        public string EncryptTextToBase64(string toEncrypt)
        {
            byte[] toEncrStrData = EncryptData(ASCIIEncoding.ASCII.GetBytes(toEncrypt));

            return Convert.ToBase64String(toEncrStrData);
        }

        /// <summary>
        /// Decrypt a base64 encoded encrypted data
        /// 
        /// Used to decryp password
        /// </summary>
        /// <param name="toDecrypt">Base64 encoded encrypted data</param>
        /// <returns>Decrypted text</returns>
        public string DecryptTextFromBase64(string toDecrypt)
        {
            byte[] encrData = Convert.FromBase64String(toDecrypt);

            return ASCIIEncoding.ASCII.GetString(DecryptData(encrData));
        }

        /// <summary>
        /// Encrypt the AES key using the IEncryptor interface. This method creates the
        /// DigestData
        /// </summary>
        /// <param name="digestEncryptor">IDigestEncryptor object</param>
        /// <returns>The DigestData after the key and IV have been encrypted</returns>
        public DigestData EncryptKey(IDigestEncryptor digestEncryptor)
        {
            // Get the AES key and IV to encrypt them
            byte[] aesKeyAndIV = new byte[aesProvider.Key.Length + aesProvider.IV.Length];

            Buffer.BlockCopy(aesProvider.Key, 0, aesKeyAndIV, 0, aesProvider.Key.Length);
            Buffer.BlockCopy(aesProvider.IV, 0, aesKeyAndIV, aesProvider.Key.Length, aesProvider.IV.Length);

            digestEncryptor.Encrypt(aesKeyAndIV);

            return digestEncryptor.Digest;
        }

        #endregion

        private byte[] ProcessCryptoStream(ICryptoTransform cryptoTransform, byte[] inputData)
        {
            byte[] outputData = null;

            using (MemoryStream msCrypt = new MemoryStream(inputData))
            {
                using (CryptoStream cryptoStream = new CryptoStream(msCrypt, cryptoTransform, CryptoStreamMode.Read))
                {
                    using (MemoryStream msOutStream = new MemoryStream())
                    {
                        int blockSize = 64;
                        int nbRead = 0;
                        byte[] outputBlock = new byte[blockSize];
                        do
                        {
                            nbRead = cryptoStream.Read(outputBlock, 0, blockSize);
                            msOutStream.Write(outputBlock, 0, nbRead);
                        }
                        while (nbRead == blockSize);

                        outputData = msOutStream.ToArray();
                    }
                }
            }

            return outputData;
        }
    }
}
