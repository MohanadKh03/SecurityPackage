using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        static string ceaser_CipherEncrypt(string s, int key)
        {
            //Console.WriteLine(input_string);
            //Console.WriteLine(key);
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            s = s.ToUpper();
            string output_string = "";
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == ' ')
                {
                    output_string += " ";
                }
                else
                {
                    int num = s[i] - 65;
                    num += key;
                    num %= 26;
                    output_string += alpha[num];
                }
            }
            return output_string;
        }

        static string ceaser_CipherDecrypt(string s, int key)
        {
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            s = s.ToUpper();
            //Console.WriteLine(input_string);
            //Console.WriteLine(key);
            string output_string = "";
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == ' ')
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
                    int num = s[i] - 65;
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

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            return ceaser_CipherEncrypt(plainText, key);
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            return ceaser_CipherDecrypt(cipherText, key);
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            int num = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                num = plainText[i] - cipherText[i];
                Console.WriteLine(plainText[i] + " " + cipherText[i] + " " + num);
                if (num < 0)
                {
                    num += (26);
                }
                if (num > 0)
                {
                    break;
                }
            }
            return num % 26;
        }
    }
}
