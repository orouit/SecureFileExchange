/**
 * CodeProject license
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Core.Security
{
    public struct FileDescription
    {
        public string FileName;
        public string MimeType;
        public string Application;
        public string EncryptionAlgorithm;

        public FileDescription(string fileName, string mimeType, string application, string encryptionAlgorithm)
        {
            FileName = fileName;
            MimeType = mimeType;
            Application = application;
            EncryptionAlgorithm = encryptionAlgorithm;
        }
    }
}
