using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES des = new DES();
            string key1 = key[0];
            string key2 = key[1];
            string plain_first_stage = des.Decrypt(cipherText, key1);
            string plain_second_stage = des.Encrypt(plain_first_stage, key2);
            string plain_text = des.Decrypt(plain_second_stage, key1);
            return plain_text;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string key1 = key[0];
            string key2 = key[1];
            DES des = new DES();
            string first_cipher =des.Encrypt(plainText, key1);
            string second_cipher = des.Decrypt(first_cipher, key2);
            string Last_Cipher = des.Encrypt(second_cipher, key1);

            return Last_Cipher;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
