/**
 * CodeProject license
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Newtonsoft.Json;

namespace Core.Security
{
    /// <summary>
    /// Header containing information of the encrypted data. The header is a serialized 
    /// using Json
    /// 
    /// Format of the complete encrypted file:
    /// byte[0]: Header format. 0 = Json
    /// byte[1 - 4]: Length of the header
    /// byte[5 - Length + 5]: Header
    /// byte[Length + 6 - EOF]: Encrypted data
    /// </summary>
    [Serializable]
    public class EncryptedDataHeader
    {
        #region Serializable fields

        [JsonProperty]
        private string fileName;

        [JsonProperty]
        private string mime;

        [JsonProperty]
        private string application;

        [JsonProperty]
        private string encryptionAlgorithm;

        [JsonProperty]
        private string userID;

        [JsonProperty]
        private DigestData signature;

        [JsonProperty]
        private EncryptedKey[] encryptedKeys;

        #endregion

        public EncryptedDataHeader(string fileName, string userID)
        {
            this.fileName = fileName;
            this.userID = userID;
        }

        [JsonIgnore]
        public string FileName
        {
            get { return fileName; }
        }

        [JsonIgnore]
        public string MIME
        {
            get { return mime; }
            set { mime = value;}
        }

        [JsonIgnore]
        public string Application
        {
            get { return application; }
            set { application = value; }
        }

        [JsonIgnore]
        public string EncryptionAlgorithm
        {
            get { return encryptionAlgorithm; }
            set { encryptionAlgorithm = value; }
        }

        [JsonIgnore]
        public string UserID
        {
            get { return userID; }
        }

        [JsonIgnore]
        public DigestData Signature
        {
            get { return signature; }
            set { signature = value; }
        }

        [JsonIgnore]
        public EncryptedKey[] EncryptedKeys
        {
            get { return encryptedKeys; }
            set { encryptedKeys = value; }
        }
    }
}
