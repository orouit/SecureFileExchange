/**
 * CodeProject license
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Security.Cryptography;

namespace Core.Security
{
    /// <summary>
    /// Interface to encrypt a DigestData
    /// </summary>
    public interface IDigestEncryptor
    {
        /// <summary>
        /// Encrypt a data buffer
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        void Encrypt(byte[] data);

        /// <summary>
        /// Decrypt the data that was encrypted previously and stored in a DigestData object
        /// </summary>
        /// <returns></returns>
        byte[] Decrypt();

        /// <summary>
        /// Gets the DigestData object that resulted of the encryption
        /// </summary>
        DigestData Digest { get; }
    }
}
