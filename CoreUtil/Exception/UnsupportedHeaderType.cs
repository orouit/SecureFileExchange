using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Core.Exception
{
    public class UnsupportedHeaderType : ApplicationException
    {
        private byte headerType;

        public UnsupportedHeaderType(byte headerType)
            : base(string.Format("Header type [{0}] is unsupported", headerType))
        {
            this.headerType = headerType;
        }

        public int HeaderType
        {
            get { return headerType; }
        }
    }
}
