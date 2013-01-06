/**
 * CodeProject license
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Core.Security
{
    /// <summary>
    /// Interface used to encrypt the data file content
    /// </summary>
    public interface IEncryptProcess
    {
        /// <summary>
        /// Encrypt data
        /// </summary>
        /// <param name="dataToEncrypt">Data buffer to encrypt</param>
        /// <returns>Encrypted data</returns>
        byte[] EncryptData(byte[] dataToEncrypt);

        /// <summary>
        /// Decrypt data
        /// </summary>
        /// <param name="dataToDecrypt">Data buffer to decrypt</param>
        /// <returns>Decrypted data</returns>
        byte[] DecryptData(byte[] dataToDecrypt);

        /// <summary>
        /// Encrypt the key that was used to encrypt the data using the given
        /// IDigestEncryptor object
        /// </summary>
        /// <param name="digestEncryptor"></param>
        /// <returns></returns>
        DigestData EncryptKey(IDigestEncryptor digestEncryptor);
    }
}
