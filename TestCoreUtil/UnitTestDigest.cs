/**
 * © ORConcept 2012
 */

using Core.Extension;
using Core.Security;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace TestCoreUtil
{
    /// <summary>
    /// Summary description for UnitTest1
    /// </summary>
    [TestClass]
    public class UnitTestDigest
    {
        const string 
            TEXT_TO_SIGN = "This is the text to be signed with owner Public Key",
            USER_ID_SRCE = "file.owner@mailaddress.com",
            USER_ID_DEST1 = "file.recipient@mailaddress.com",
            FILE_NAME = "file.txt",
            MIME_TEXT = "text/plain",
            MIME_JPG = "image/jpeg",
            ALGO_AES = "AES256",
            APP_NOTEPAD = "notepad.exe",
            APP_SLIDESHOW = "PaintDotNet.exe",
            IMG_FILE_NAME = "the-millenium-falcon-15219-1920x1080.jpg",
            PASSWORD = "starwars";

        public UnitTestDigest()
        {
            //
            // TODO: Add constructor logic here
            //
        }

        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        //
        // You can use the following additional attributes as you write your tests:
        //
        // Use ClassInitialize to run code before running the first test in the class
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // Use ClassCleanup to run code after all tests in a class have run
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Use TestInitialize to run code before running each test 
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        [TestMethod]
        public void TestEncryptDecryptKey()
        {
            AesCryptoServiceProvider aesServiceProvider = new AesCryptoServiceProvider();
            aesServiceProvider.KeySize = 256;
            aesServiceProvider.GenerateKey();
            aesServiceProvider.GenerateIV();

            byte[] key = aesServiceProvider.Key;
            byte[] iv = aesServiceProvider.IV;

            byte[] aesKeyAndIV = new byte[key.Length + iv.Length];
            Buffer.BlockCopy(key, 0, aesKeyAndIV, 0, key.Length);
            Buffer.BlockCopy(iv, 0, aesKeyAndIV, key.Length, iv.Length);

            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
            DigestData rsaDigestEncrypt = new RSAOAEPEncryptor(rsaProvider);
            ((IDigestEncryptor)rsaDigestEncrypt).Encrypt(aesKeyAndIV);

            string jsonSerialized = JsonConvert.SerializeObject(rsaDigestEncrypt);

            DigestData rsaJsonDigest = (DigestData)JsonConvert.DeserializeObject(jsonSerialized, typeof(DigestData));

            IDigestEncryptor rsaDigestDecryp = RSADigestFactory.CreateDigestData(rsaJsonDigest, rsaProvider) as IDigestEncryptor;
            Assert.IsNotNull(rsaDigestDecryp);
            byte[] decryptedKeyAndIV = rsaDigestDecryp.Decrypt();
            bool equals = aesKeyAndIV.HasSameContent(decryptedKeyAndIV);
            Assert.IsTrue(equals);
        }

        [TestMethod]
        public void TestEncryptionSignature()
        {
            byte[] byteText = ASCIIEncoding.ASCII.GetBytes(TEXT_TO_SIGN);

            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider();
            DigestData rsaDigestSigned = new RSASHA1Signature(rsaProvider);

            ((IDigestSignature)rsaDigestSigned).Sign(byteText);

            string jsonSerialized = JsonConvert.SerializeObject(rsaDigestSigned);
            DigestData rsaJsonDigest = (DigestData)JsonConvert.DeserializeObject(jsonSerialized, typeof(DigestData));

            IDigestSignature rsaDigestVerify = new RSASHA1Signature(rsaJsonDigest, rsaProvider);
            bool verified = rsaDigestVerify.Verify(byteText);

            Assert.IsTrue(verified);
        }

        [TestMethod]
        public void TestEncrypteDatadHeader()
        {
            EncryptedDataHeader encryptedHeader = new EncryptedDataHeader(FILE_NAME, USER_ID_SRCE);

            encryptedHeader.Application = APP_NOTEPAD;
            encryptedHeader.EncryptionAlgorithm = ALGO_AES;
            encryptedHeader.MIME = MIME_TEXT;

            AesCryptoServiceProvider aesServiceProvider = new AesCryptoServiceProvider();
            aesServiceProvider.KeySize = 256;
            aesServiceProvider.GenerateKey();
            aesServiceProvider.GenerateIV();

            byte[] key = aesServiceProvider.Key;
            byte[] iv = aesServiceProvider.IV;

            byte[] aesKeyAndIV = new byte[key.Length + iv.Length];
            Buffer.BlockCopy(key, 0, aesKeyAndIV, 0, key.Length);
            Buffer.BlockCopy(iv, 0, aesKeyAndIV, key.Length, iv.Length);

            // Encrypt the AES key with the public key of the OlivierCodepro certificate
            RSACryptoServiceProvider rsaProviderOlivierCodepro = new RSACryptoServiceProvider();
            DigestData rsaDigestEncrypt = new RSAOAEPEncryptor(rsaProviderOlivierCodepro);
            ((IDigestEncryptor)rsaDigestEncrypt).Encrypt(aesKeyAndIV);

            EncryptedKey encryptedAesKeyForOlivierCodepro = new EncryptedKey(USER_ID_DEST1, rsaDigestEncrypt);
            encryptedHeader.EncryptedKeys = new EncryptedKey[] { encryptedAesKeyForOlivierCodepro };

            // Sign the test BEFORE it is encrypted using OlivierRouit private key
            byte[] byteText = ASCIIEncoding.ASCII.GetBytes(TEXT_TO_SIGN);

            RSACryptoServiceProvider rsaProviderOlivierRouit = new RSACryptoServiceProvider();
            DigestData rsaDigestSigned = new RSASHA1Signature(rsaProviderOlivierRouit);

            ((IDigestSignature)rsaDigestSigned).Sign(byteText);

            encryptedHeader.Signature = rsaDigestSigned;

            string jsonSerialized = JsonConvert.SerializeObject(encryptedHeader);

            EncryptedDataHeader encryptedHeaderDeserialized = JsonConvert.DeserializeObject<EncryptedDataHeader>(jsonSerialized);

            // Process the Signature DigestData
            IDigestSignature signDigest = RSADigestFactory.CreateDigestData(encryptedHeaderDeserialized.Signature, rsaProviderOlivierRouit) as IDigestSignature;
            bool verified = signDigest.Verify(byteText);
            Assert.IsTrue(verified);

            // Process the encrypted DigestData
            IDigestEncryptor encryptDigest = RSADigestFactory.CreateDigestData(encryptedHeaderDeserialized.EncryptedKeys.Where(k => k.UserID == USER_ID_DEST1).First().Encrypted, rsaProviderOlivierCodepro) as IDigestEncryptor;
            byte[] decryptedKeyAndIV = encryptDigest.Decrypt();
            bool equals = aesKeyAndIV.HasSameContent(decryptedKeyAndIV);
            Assert.IsTrue(equals);
        }

        [TestMethod]
        public void TestFileEncryption()
        {
            // Load the file to encrypt
            byte[] imgData = File.ReadAllBytes(IMG_FILE_NAME);

            AESEncryptor aesEncryptor = new AESEncryptor(PASSWORD);

            RSACryptoServiceProvider rsaProviderOlivierCodepro = new RSACryptoServiceProvider();
            RSAOAEPEncryptor rsaDigestEncrypt = new RSAOAEPEncryptor(rsaProviderOlivierCodepro);

            RSACryptoServiceProvider rsaProviderOlivierRouit = new RSACryptoServiceProvider();
            RSASHA1Signature rsaDigestSigned = new RSASHA1Signature(rsaProviderOlivierRouit);

            // Encrypt the file data, the key and sign the original file data
            EncryptedFile encryptFile = new EncryptedFile(imgData,
                new FileDescription(IMG_FILE_NAME, MIME_JPG, APP_SLIDESHOW, ALGO_AES),
                aesEncryptor,
                new Recipient[] { new Recipient(USER_ID_DEST1, rsaDigestEncrypt) },
                new Owner(USER_ID_SRCE, rsaDigestSigned));

            // Build an EncryptedFile instance from the encrypted content with header
            EncryptedFile encryptFileOut = new EncryptedFile(encryptFile.EncryptedContent);

            EncryptedDataHeader encryptedHeader = encryptFileOut.EncryptedHeader;

            // Process the encrypted DigestData to extract the AES key
            IDigestEncryptor encryptDigest = RSADigestFactory.CreateDigestData(encryptedHeader.EncryptedKeys.Where(k => k.UserID == USER_ID_DEST1).First().Encrypted, rsaProviderOlivierCodepro) as IDigestEncryptor;
            byte[] decryptedKeyAndIV = encryptDigest.Decrypt();

            IEncryptProcess aesDecryptor = new AESEncryptor(decryptedKeyAndIV);
            byte[] decryptedFileData = aesDecryptor.DecryptData(encryptFileOut.EncryptedFileData);

            // Process the Signature DigestData
            IDigestSignature signDigest = RSADigestFactory.CreateDigestData(encryptedHeader.Signature, rsaProviderOlivierRouit) as IDigestSignature;
            bool verified = signDigest.Verify(decryptedFileData);
            Assert.IsTrue(verified);
        }
    }
}
