/**
 * CodeProject license
 */

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Core.Security
{
    [Serializable]
    public class EncryptedKey
    {
        [JsonProperty]
        private string userID;

        [JsonProperty]
        private DigestData encrypted;

        public EncryptedKey(string userID, DigestData encrypted)
        {
            this.userID = userID;
            this.encrypted = encrypted;
        }

        [JsonIgnore]
        public string UserID
        {
            get { return userID; }
        }

        [JsonIgnore]
        public DigestData Encrypted
        {
            get { return encrypted; }
            protected set { encrypted = value; }
        }
    }
}
