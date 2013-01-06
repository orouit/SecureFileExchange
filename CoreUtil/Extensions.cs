/**
 * CodeProject license
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Core.Extension
{
    public static class Extensions
    {
        public static bool HasSameContent(this byte[] org, byte[] other)
        {
            bool ret = org.Length == other.Length;

            for (int n = 0; n < org.Length; n++)
            {
                if (org[n] != other[n])
                {
                    ret = false;
                    break;
                }
            }

            return ret;
        }
    }
}
