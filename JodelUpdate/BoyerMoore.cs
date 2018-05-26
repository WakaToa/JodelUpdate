using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JodelUpdate
{
    public class BoyerMoore
    {
        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        private readonly byte[] _needle;
        private readonly int[] _charTable;
        private readonly int[] _offsetTable;

        public static IEnumerable<int> Search(string needle, byte[] haystack)
        {
            return new BoyerMoore(StringToByteArray(needle)).Search(haystack);
        }

        public BoyerMoore(byte[] needle)
        {
            this._needle = needle;
            this._charTable = MakeByteTable(needle);
            this._offsetTable = MakeOffsetTable(needle);
        }

        public IEnumerable<int> Search(byte[] haystack)
        {
            if (_needle.Length == 0)
                yield break;

            for (var i = _needle.Length - 1; i < haystack.Length;)
            {
                int j;

                for (j = _needle.Length - 1; _needle[j] == haystack[i]; --i, --j)
                {
                    if (j != 0)
                        continue;

                    yield return i;
                    i += _needle.Length - 1;
                    break;
                }

                i += Math.Max(_offsetTable[_needle.Length - 1 - j], _charTable[haystack[i]]);
            }
        }

        private static int[] MakeByteTable(byte[] needle)
        {
            const int ALPHABET_SIZE = 256;
            var table = new int[ALPHABET_SIZE];

            for (var i = 0; i < table.Length; ++i)
                table[i] = needle.Length;

            for (var i = 0; i < needle.Length - 1; ++i)
                table[needle[i]] = needle.Length - 1 - i;

            return table;
        }

        private static int[] MakeOffsetTable(byte[] needle)
        {
            var table = new int[needle.Length];
            var lastPrefixPosition = needle.Length;

            for (var i = needle.Length - 1; i >= 0; --i)
            {
                if (IsPrefix(needle, i + 1))
                    lastPrefixPosition = i + 1;

                table[needle.Length - 1 - i] = lastPrefixPosition - i + needle.Length - 1;
            }

            for (var i = 0; i < needle.Length - 1; ++i)
            {
                var slen = SuffixLength(needle, i);
                table[slen] = needle.Length - 1 - i + slen;
            }

            return table;
        }

        private static bool IsPrefix(byte[] needle, int p)
        {
            for (int i = p, j = 0; i < needle.Length; ++i, ++j)
                if (needle[i] != needle[j])
                    return false;

            return true;
        }

        private static int SuffixLength(byte[] needle, int p)
        {
            var len = 0;

            for (int i = p, j = needle.Length - 1; i >= 0 && needle[i] == needle[j]; --i, --j)
                ++len;

            return len;
        }
    }
}
