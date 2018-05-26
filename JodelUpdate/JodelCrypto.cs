using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace JodelUpdate
{
    //https://bitbucket.org/cfib90/ojoc-keyhack/src/b8fc232ebe98f2d47c9d30828c94b0026576b286/x86/decrypt.c?at=public&fileviewer=file-view-default
    public class JodelCrypto
    {
        static int CLIENT_SECRET_SIZE = 40;
        static int CRYPTTABLE_SIZE = 256;
        private static string SIGNATURE = "a4a8d4d7b09736a0f65596a868cc6fd620920fb0"; //cert app signature


        public static string DecryptHmacSecret(byte[] xorKey)
        {
            var encryptionKey = GenerateEncryptionKey();

            var clientSecret = new char[CLIENT_SECRET_SIZE + 1];
            var secretCounter = 0;

            for (var secretIndex = 0; secretIndex < CLIENT_SECRET_SIZE; ++secretIndex)
            {
                var encryptionKeyByte = encryptionKey[secretIndex + 1];
                secretCounter += encryptionKeyByte;
                while (secretCounter >= CRYPTTABLE_SIZE)
                {
                    secretCounter = (secretCounter - CRYPTTABLE_SIZE);
                }
                encryptionKey[secretIndex + 1] = encryptionKey[secretCounter];
                encryptionKey[secretCounter] = encryptionKeyByte;
                clientSecret[secretIndex] = (char)(xorKey[secretIndex] ^ encryptionKey[(byte)(encryptionKey[secretIndex + 1] + encryptionKeyByte)]);
                if (!char.IsLetter(clientSecret[secretIndex]))
                {
                    // We assume from the history of keys that a valid key only
                    // contains printable characters
                    return "";
                }
            }
            clientSecret[CLIENT_SECRET_SIZE] = (char)0;

            return new string(clientSecret.Take(clientSecret.Length - 1).ToArray());
        }

        private static char[] GenerateEncryptionKey()
        {
            var encryptionKey = new char[CRYPTTABLE_SIZE];
            var signatureLength = SIGNATURE.Length;
            var shuffleCounter = 0;

            for (var i = 0; i < CRYPTTABLE_SIZE; i++)
                encryptionKey[i] = (char)i;

            for (var shuffleIndex = 0; shuffleIndex < CRYPTTABLE_SIZE; ++shuffleIndex)
            {
                int encryptionKeyByte = encryptionKey[shuffleIndex];
                shuffleCounter += SIGNATURE[shuffleIndex % signatureLength];
                shuffleCounter += encryptionKeyByte;
                while (shuffleCounter >= CRYPTTABLE_SIZE)
                {
                    shuffleCounter = (shuffleCounter - CRYPTTABLE_SIZE);
                }
                encryptionKey[shuffleIndex] = encryptionKey[shuffleCounter];
                encryptionKey[shuffleCounter] = (char)encryptionKeyByte;
            }

            return encryptionKey;
        }
    }
}