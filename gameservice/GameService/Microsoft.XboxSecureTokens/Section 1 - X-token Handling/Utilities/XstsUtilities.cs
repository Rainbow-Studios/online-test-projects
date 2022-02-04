//-----------------------------------------------------------------------------
// XstsUtil.cs
//
// Advanced Technology Group (ATG)
// Copyright (C) Microsoft Corporation. All rights reserved.
//-----------------------------------------------------------------------------

#pragma warning disable IDE0063 // Use simple 'using' statement

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;

namespace Microsoft.XboxSecureTokens
{
    //  SECTION 1 - Helpful functions for decrypting the tokens
    static class XstsUtilities
    {
        internal static async Task<byte[]> DecryptAsync(byte[] cipher, byte[] key, byte[] iv)
        {
            if (cipher == null)
            {
                throw new ArgumentNullException("cipher");
            }

            return await Task.Run(() =>
            {
                using (RijndaelManaged symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.Mode = CipherMode.CBC;
                    byte[] plainTextBytes = new byte[cipher.Length];
                    using (ICryptoTransform decryptor = symmetricKey.CreateDecryptor(key, iv))
                    {
                        return Decrypt(decryptor, cipher);
                    }
                }
            });
        }

        internal static byte[] Decrypt(ICryptoTransform decryptor, byte[] cipher)
        {
            if (decryptor == null)
            {
                throw new ArgumentNullException("decryptor");
            }

            if (cipher == null)
            {
                throw new ArgumentNullException("cipher");
            }

            byte[] decryptedBytes = null;

            using (var ms = new MemoryStream(cipher))
            {
                using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    decryptedBytes = new byte[cipher.Length];
                    int count = cryptoStream.Read(decryptedBytes, 0, decryptedBytes.Length);
                    decryptedBytes = decryptedBytes.Take(count).ToArray();
                }
            }

            return decryptedBytes;
        }

        internal static async Task<string> DecompressAsync(byte[] input)
        {
            return await Task.Run(() =>
            {
                using (var inputStream = new MemoryStream(input))
                {
                    using (var deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress))
                    {
                        using (var reader = new StreamReader(deflateStream))
                        {
                            return reader.ReadToEnd();
                        }
                    }
                }
            });
        }

        internal static byte[] FromBase64Url(string toBeDecoded)
        {
            // Add padding
            toBeDecoded = toBeDecoded.PadRight(toBeDecoded.Length + (4 - toBeDecoded.Length % 4) % 4, '=');

            // Base64 URL encoded to Base 64 encoded
            toBeDecoded = toBeDecoded.Replace('-', '+').Replace('_', '/');

            // Base 64 decode
            byte[] raw = Convert.FromBase64String(toBeDecoded);
            return raw;
        }

        internal static string ToBase64Url(byte[] arg)
        {
            if (arg == null)
            {
                throw new ArgumentNullException("arg");
            }
            string s = Convert.ToBase64String(arg);
            s = s.Split(XstsConstants.Base64PadCharacter)[0]; // Remove any trailing padding
            s = s.Replace(XstsConstants.Base64Character62, XstsConstants.Base64UrlCharacter62); // 62nd char of encoding
            s = s.Replace(XstsConstants.Base64Character63, XstsConstants.Base64UrlCharacter63); // 63rd char of encoding

            return s;
        }

        internal static byte[] ArrayConcat(params byte[][] args)
        {
            if (args == null)
            {
                return new byte[0];
            }

            var nonNullArgs = args.Where(a => a != null);

            int resultLen = nonNullArgs.Sum(a => a.Length);
            byte[] res = new byte[resultLen];

            int index = 0;
            foreach (byte[] bArr in nonNullArgs)
            {
                Buffer.BlockCopy(bArr, 0, res, index, bArr.Length);
                index += bArr.Length;
            }

            return res;
        }

        internal static byte[] SignHmac(byte[] data, byte[] key)
        {
            using (HMACSHA256 hmacSha = new HMACSHA256(key))
            {
                byte[] sig = hmacSha.ComputeHash(data);
                return sig;
            }
        }

        internal static void VerifyAuthenticationTag(byte[] aad, byte[] iv, byte[] cipherText, byte[] hmacKey, byte[] authTag)
        {
            byte[] aadBitLength = BitConverter.GetBytes((ulong)(aad.Length * 8));

            // AL value must be in Big Endian
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(aadBitLength);
            }

            byte[] dataToSign = XstsUtilities.ArrayConcat(aad, iv, cipherText, aadBitLength);
            byte[] hash = XstsUtilities.SignHmac(dataToSign, hmacKey);
            byte[][] computedAuthTag = SplitSecretKey(hash);

            // Check if the auth tag is equal
            // The authentication tag is the first half of the hmac result
            if (!authTag.FixedTimeEquals(computedAuthTag[0]))
            {
                throw new InvalidOperationException("Authentication tag does not match with the computed hash.");
            }
        }
        internal static byte[][] SplitSecretKey(byte[] val)
        {
            // val should be even length
            if (val.Length % 2 != 0)
            {
                throw new ArgumentException();
            }

            int midpoint = val.Length / 2;

            byte[] firstHalf = new byte[midpoint];
            byte[] secondHalf = new byte[midpoint];
            Buffer.BlockCopy(val, 0, firstHalf, 0, midpoint);
            Buffer.BlockCopy(val, midpoint, secondHalf, 0, midpoint);

            return new[] { firstHalf, secondHalf };
        }

        /// <summary>
        /// Determine the equality of two byte sequences in an amount of time which depends on
        /// the length of the sequences, but not the values. This helps prevent timing attacks.
        /// inspired by CryptographicOperations
        /// https://github.com/dotnet/runtime/blob/master/src/libraries/System.Security.Cryptography.Primitives/src/System/Security/Cryptography/CryptographicOperations.cs
        /// </summary>
        /// <param name="left">First buffer to compare</param>
        /// <param name="right">Second buffer to compare</param>
        /// <returns>true if left and right are the same length and contents</returns>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals(this byte[] left, byte[] right)
        {
            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.
            if (left == null && right == null)
            {
                return true;
            }
            if (left == null || right == null || left.Length != right.Length)
            {
                return false;
            }
            int length = left.Length;
            int accum = 0;
            for (int i = 0; i < length; i++)
            {
                accum |= left[i] - right[i];
            }
            return accum == 0;
        }
    }
}

#pragma warning restore IDE0063 // Use simple 'using' statement
