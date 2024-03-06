using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        static Dictionary<KeyValuePair<char, char>, char> encryptingDictionary = new Dictionary<KeyValuePair<char, char>, char>();
        static Dictionary<KeyValuePair<char, char>, char> decryptingDictionary = new Dictionary<KeyValuePair<char, char>, char>();
        static Dictionary<KeyValuePair<char, char>, char> analysingDictionary = new Dictionary<KeyValuePair<char, char>, char>();

        private void MakeEncryptingDictionary()
        {
            char start = 'a';
            char curr;
            for (int i = 0; i < 26; i++)
            {
                curr = (char)(start + i);
                for (int j = 0; j < 26; j++)
                {
                    KeyValuePair<char, char> keyValue = new KeyValuePair<char, char>((char)('a' + i), (char)('a' + j));
                    encryptingDictionary[keyValue] = curr;
                    curr++;
                    if (curr > 'z')
                        curr = 'a';
                }
            }
        }
        private void MakeDecryptiongDictionary()
        {
            char start = 'a';
            for (int i = 0; i < 26; i++)
            {
                char x = start;
                for (int j = 0; j < 26; j++)
                {
                    KeyValuePair<char, char> keyValue = new KeyValuePair<char, char>((char)(i + 'a'), x);
                    decryptingDictionary[keyValue] = (char)(j + 'a');
                    x++;
                    if (x > 'z') x = 'a';
                }
                start++;
            }
        }

        void MakeAnalysingDictionary()
        {
            char start = 'a';
            for (int i = 0; i < 26; i++)
            {
                char x = start;
                for (int j = 0; j < 26; j++)
                {

                }
            }
        }

        private void MakeDictionaries()
        {
            MakeEncryptingDictionary();
            MakeDecryptiongDictionary();
        }

        public AutokeyVigenere()
        {
            MakeDictionaries();
        }


        public string Analyse(string plainText, string cipherText)
        {
            StringBuilder key = new StringBuilder("");
            for (int i = 0; i < plainText.Length; i++)
            {
                KeyValuePair<char, char> keyValue = new KeyValuePair<char, char>(char.ToLower(plainText[i]), char.ToLower(cipherText[i]));
                key.Append(decryptingDictionary[keyValue]);
            }
            int ctr = 0;
            int start = -1;
            bool flag = false;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (key[i] != plainText[ctr])
                    flag = false;
                else
                    start = i;
                while (i < plainText.Length && key[i] == plainText[ctr])
                {
                    ctr++;
                    i++;
                    flag = true;
                }
            }
            if (flag)
                key = key.Remove(start, key.Length - start);
            return key.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            int toBeAdded = 0;
            int startIndex = key.Length;
            while (key.Length < cipherText.Length)
            {
                char keyIndex = key[toBeAdded];
                char cipherIndex = char.ToLower(cipherText[toBeAdded]);
                KeyValuePair<char, char> keyValue = new KeyValuePair<char, char>(keyIndex, cipherIndex);
                key += decryptingDictionary[keyValue];
                toBeAdded++;
            }
            StringBuilder decryptedWord = new StringBuilder("");
            for (int i = 0; i < key.Length; i++)
            {
                KeyValuePair<char, char> keyValue = new KeyValuePair<char, char>(key[i], char.ToLower(cipherText[i]));
                decryptedWord.Append(decryptingDictionary[keyValue]);
            }
            return decryptedWord.ToString();
        }

        public string Encrypt(string plainText, string key)
        {

            int toBeAdded = 0;
            while (key.Length < plainText.Length)
            {
                key += plainText[toBeAdded++];
            }

            StringBuilder decipheredWord = new StringBuilder("");
            for (int i = 0; i < key.Length; i++)
            {
                KeyValuePair<char, char> keyValue = new KeyValuePair<char, char>(plainText[i], key[i]);
                decipheredWord.Append(encryptingDictionary[keyValue]);
            }
            return decipheredWord.ToString();
        }
    }
}
