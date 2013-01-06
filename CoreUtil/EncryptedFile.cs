/**
 * CodeProject license
 */

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Core.Exception;

namespace Core.Security
{
    public class EncryptedFile
    {
        const int HEAD_LEN = 5;
        const byte JSON_TYPE = 0;

        /// <summary>
        /// Raw data content of the encrypted file (Header + encrypted data)
        /// </summary>
        private byte[] rawEncryptedData;

        /// <summary>
        /// Encrypted file data
        /// </summary>
        private byte[] encryptedFileData;

        /// <summary>
        /// Encrypted data header, contains the info so the recipients can decrypt the 
        /// data using their private key
        /// </summary>
        private EncryptedDataHeader encryptedHeader;

        /// <summary>
        /// Build an EncryptedFile object from the file data, encryption information and
        /// signature information
        /// </summary>
        /// <param name="fileData">File data to encrypt</param>
        /// <param name="fileDescrition">File description</param>
        /// <param name="fileEncryptor">IFileEncryptor interface</param>
        /// <param name="recipients">Set of recipient for the encrypted file</param>
        /// <param name="owner">Owner of the original file</param>
        public EncryptedFile(byte[] fileData,
            FileDescription fileDescrition,
            IEncryptProcess fileEncryptor,
            Recipient[] recipients,
            Owner owner)
        {
            List<EncryptedKey> encryptedKeys = new List<EncryptedKey>();

            // Encrypt the data
            byte[] encryptedData = fileEncryptor.EncryptData(fileData);

            // Encrypt the encryption key for each recipient
            foreach (Recipient recipient in recipients)
            {
                encryptedKeys.Add(new EncryptedKey(recipient.UserId, fileEncryptor.EncryptKey(recipient.DigestEncryptor)));
            }

            // Sign the original data
            owner.DigestSignature.Sign(fileData);
            DigestData signedDigest = owner.DigestSignature.Digest;

            EncryptedDataHeader encryptedHeader = new EncryptedDataHeader(fileDescrition.FileName, owner.UserId);
            encryptedHeader.Application = fileDescrition.Application;
            encryptedHeader.MIME = fileDescrition.MimeType;
            encryptedHeader.EncryptionAlgorithm = fileDescrition.EncryptionAlgorithm;

            encryptedHeader.EncryptedKeys = encryptedKeys.ToArray();

            encryptedHeader.Signature = signedDigest;

            BuildRawData(encryptedData, encryptedHeader);
        }

        /// <summary>
        /// Build an EncryptedFile object from the data result of the encryption.
        /// </summary>
        /// <param name="encryptedData"></param>
        public EncryptedFile(byte[] encryptedData)
        {
            // Get the header type
            byte headerType = encryptedData[0];

            if (headerType != JSON_TYPE)
            {
                throw new UnsupportedHeaderType(headerType);
            }

            // Get the header length
            int offset = 1;
            byte[] jsonHeaderLengthBytes = new byte[sizeof(UInt32)];
            Buffer.BlockCopy(encryptedData, offset, jsonHeaderLengthBytes, 0, sizeof(UInt32));
            UInt32 jsonHeaderLength = BitConverter.ToUInt32(jsonHeaderLengthBytes, 0);

            // Get the Json serialized EncryptedDataHeader 
            offset += sizeof(UInt32);
            byte[] jsonHeaderBytes = new byte[jsonHeaderLength];
            Buffer.BlockCopy(encryptedData, offset, jsonHeaderBytes, 0, (int) jsonHeaderLength);

            // Get the encrypted file data
            offset += (int) jsonHeaderLength;
            int encrFileDataLength = encryptedData.Length - (int)jsonHeaderLength - sizeof(UInt32) - 1;
            encryptedFileData = new byte[encrFileDataLength];
            Buffer.BlockCopy(encryptedData, offset, encryptedFileData, 0, encrFileDataLength); 

            // Deserialize the the header
           encryptedHeader = JsonConvert.DeserializeObject<EncryptedDataHeader>(ASCIIEncoding.ASCII.GetString(jsonHeaderBytes));
        }

        /// <summary>
        /// Get the encrypted file content, including the Json serialized header.
        /// </summary>
        public byte[] EncryptedContent
        {
            get { return rawEncryptedData; }
        }

        /// <summary>
        /// Encrypted data header deserialized
        /// </summary>
        public EncryptedDataHeader EncryptedHeader
        {
            get { return encryptedHeader; }
        }

        /// <summary>
        /// Encrypted file data
        /// </summary>
        public byte[] EncryptedFileData
        {
            get { return encryptedFileData; }
        }

        private void BuildRawData(byte[] encryptedData, EncryptedDataHeader encryptedHeader)
        {
            string jsonHeader = JsonConvert.SerializeObject(encryptedHeader);
            byte[] jsonHeaderBuffer = ASCIIEncoding.ASCII.GetBytes(jsonHeader);

            rawEncryptedData = new byte[HEAD_LEN + jsonHeaderBuffer.Length + encryptedData.Length];
            UInt32 jsonLength = (UInt32)jsonHeaderBuffer.Length;

            byte[] jsonLengthBytes = BitConverter.GetBytes(jsonLength);

            int pos = 0;
            rawEncryptedData[0] = JSON_TYPE;
            pos += 1;
            Buffer.BlockCopy(jsonLengthBytes, 0, rawEncryptedData, pos, jsonLengthBytes.Length);
            pos += jsonLengthBytes.Length;
            Buffer.BlockCopy(jsonHeaderBuffer, 0, rawEncryptedData, pos, jsonHeaderBuffer.Length);
            pos += jsonHeaderBuffer.Length;
            Buffer.BlockCopy(encryptedData, 0, rawEncryptedData, pos, encryptedData.Length);
        }
    }
}
