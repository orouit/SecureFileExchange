/**
 * CodeProject license
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Core.Security
{
    public struct Owner
    {
        public string UserId;
        public IDigestSignature DigestSignature;

        public Owner(string userId, IDigestSignature digestSignature)
        {
            UserId = userId;
            DigestSignature = digestSignature;
        }
    }
}
