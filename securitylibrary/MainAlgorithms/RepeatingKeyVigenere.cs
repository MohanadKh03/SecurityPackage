using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {

        static Dictionary<KeyValuePair<char, char>, char> encryptingDictionary = new Dictionary<KeyValuePair<char, char>, char>();
        static Dictionary<KeyValuePair<char, char>, char> decryptingDictionary = new Dictionary<KeyValuePair<char, char>, char>();

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
            int ctr = 0;
            for (int i = 0; i < 26; i++)
            {
                char x = (char)(start + ctr);
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
        private void MakeDictionaries()
        {
            MakeEncryptingDictionary();
            MakeDecryptiongDictionary();
        }


        public RepeatingkeyVigenere()
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
                string temp = key.ToString();
                string returnedCipher = Encrypt(plainText, temp);
                if (returnedCipher.ToUpper().Equals(cipherText))
                    return key.ToString();
            }

            return null;
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            int toBeAdded = 0;
            while (key.Length < cipherText.Length)
            {
                key += key[toBeAdded++];
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
                key += key[toBeAdded++];
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