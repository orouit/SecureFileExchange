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
    public class DigestData
    {
        [JsonProperty]
        private string algorithm;

        [JsonProperty]
        private string hash;

        [JsonProperty]
        protected string digest;

        protected DigestData()
        {
        }

        public DigestData(string algorithm, string hash)
        {
            this.algorithm = algorithm;
            this.hash = hash;
        }

        [JsonIgnore]
        public string Algorithm
        {
            get { return algorithm; }
        }

        [JsonIgnore]
        public string Hash
        {
            get { return hash; }
        }

        [JsonIgnore]
        public string Digest
        {
            get { return digest; }
        }
    }
}
