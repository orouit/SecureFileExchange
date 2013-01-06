/**
 * CodeProject license
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Core.Security
{
    public struct Recipient
    {
        public string UserId;
        public IDigestEncryptor DigestEncryptor;

        public Recipient(string userId, IDigestEncryptor digestEncryptor)
        {
            UserId = userId;
            DigestEncryptor = digestEncryptor;
        }
    }
}
