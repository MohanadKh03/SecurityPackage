using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            //Console.WriteLine(input_string);
            //Console.WriteLine(key);
            string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            plainText =plainText.ToUpper();
            string output_string = "";
            for (int i = 0; i<plainText.Length; i++)
            {
                if (plainText[i] == ' ')
                {
                    output_string += " ";
                }
                else
                {
                    int num = plainText[i] - 65;
                    num += key;
                    num %= 26;
                    output_string += alpha[num];
                }
            }
            return output_string;
        }

        public string Decrypt(string cipherText, int key)
        {
            string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            //throw new NotImplementedException();
            cipherText =cipherText.ToUpper();
            //Console.WriteLine(input_string);
            //Console.WriteLine(key);
            string output_string = "";
            for (int i = 0; i<cipherText.Length; i++)
            {
                if (cipherText[i] == ' ')
                {
                    output_string += " ";
                }
                else
                {
                    //int num = s[i] - 65;
                    //num -= key;
                    //num = Math.Abs(num);
                    //num %= 26;
                    //Console.WriteLine(num);
                    //output_string += alpha[num];
                    int num = cipherText[i] - 65;
                    if (num - key < 0)
                    {
                        num += (26 - key);
                        num %= 26;
                    }
                    else
                    {
                        num -= key;
                        num %= 26;
                    }
                    output_string += alpha[num];
                }
            }
            return output_string;
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            //throw new NotImplementedException();
            for (int key = 0; key < 26; key++)
            {
                string decryptedText = Decrypt(cipherText, key);
                if (decryptedText.Equals(plainText, StringComparison.OrdinalIgnoreCase))
                {
                    return key;
                }
            }
            return -1;
        }
    }
}