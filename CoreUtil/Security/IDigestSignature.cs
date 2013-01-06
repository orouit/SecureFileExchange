/**
 * CodeProject license
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Core.Security
{
    public interface IDigestSignature
    {
        /// <summary>
        /// Sign a data buffer
        /// </summary>
        /// <param name="dataToSign">Data buffer to sign</param>
        void Sign(byte[] dataToSign);
        
        /// <summary>
        /// Verify the signature of a data buffer
        /// </summary>
        /// <param name="dataToVerify">Data buffer to verify</param>
        /// <returns></returns>
        bool Verify(byte[] dataToVerify);

        /// <summary>
        /// Gets the DigestData object that resulted of the signature
        /// </summary>
        DigestData Digest { get; }
    }
}
