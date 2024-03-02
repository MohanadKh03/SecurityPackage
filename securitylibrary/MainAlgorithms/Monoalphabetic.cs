using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            string output_s = "";
            List<char> letters1 = new List<char>{ 'A', 'B', 'C', 'D', 'E', 'F','G','H',
            'I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'
            };
            List<char> letters2 = new List<char>{ 'A', 'B', 'C', 'D', 'E', 'F','G','H',
            'I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'
            };
            Dictionary<char, char> key = new Dictionary<char, char>();
            //Dictionary<char, char> orig =  new Dictionary<char, char>();
            //Dictionary<char, char> cipher = new Dictionary<char, char>();
            for (int i = 0; i<cipherText.Length; i++)
            {
                if (!key.ContainsKey(plainText[i]))
                {
                    key.Add(plainText[i], cipherText[i]);
                    letters1.Remove(cipherText[i]);
                    letters2.Remove(plainText[i]);
                }
            }
           
            Dictionary<char, char> key2 = new Dictionary<char, char>();
            for (int i = 0; i<letters2.Count; i++)
            {
                char lastElement1 = letters2[i];
                char lastElement2 = letters1[i];
                key2.Add(lastElement1, lastElement2); ;
            }
            foreach (var x in key2)
            {
                char ch1 = x.Key;
                char ch2 = x.Value;
                key.Add(ch1, ch2);
            }
            var sortedKey = key.OrderBy(x => x.Key).ToDictionary(x => x.Key, x => x.Value);
            foreach (var x in sortedKey)
            {
                output_s+=x.Value;
            }
            output_s= output_s.ToLower();
            return output_s;
        }

        public string Decrypt(string cipherText, string key)
        {
            string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            //throw new NotImplementedException();
            cipherText= cipherText.ToUpper();
            key= key.ToUpper();
            //Dictionary<char, char> replac = new Dictionary<char, char>() {
            //    { 'D','A' },{ 'Q','B' },{ 'E','C' },{ 'P','D' },
            //    { 'R','E' },{ 'S','F' },{ 'F','G' },{ 'T','H' },
            //    { 'A','I' },{ 'W','J' },{ 'U','L' },{ 'G','M' },
            //    { 'O','N' },{ 'B','O' },{ 'V','P' },{ 'H','Q' },
            //    { 'N','R' },{ 'C','S' },{ 'M','T' },{ 'I','U' },
            //    { 'Z','V' }, {'L','W' },{ 'Y','X' },{ 'J','Y' },
            //    { 'K','Z' },
            //};
            string output_string = "";
            for (int i = 0; i<cipherText.Length; i++)
            {
                if (cipherText[i] == ' ')
                {
                    output_string += " ";
                }
                else
                {
                    int num = 0;
                    for (int j = 0; j<key.Length; j++)
                    {
                        if (cipherText[i] == key[j])
                        {
                            num = j;
                        }
                    }
                    output_string += alpha[num];
                }
            }
            return output_string;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            plainText= plainText.ToUpper();
            key = key.ToUpper();
            //Dictionary<char, char> replac = new Dictionary<char, char>() {
            //    { 'A','D' },{ 'B','Q' },{ 'C','E' },{ 'D','P' },
            //    { 'E','R' },{ 'F','S' },{ 'G','F' },{ 'H','T' },
            //    { 'I','A' },{ 'J','W' },{ 'K','X' },{ 'L','U' },
            //    { 'M','G' },{ 'N','O' },{ 'O','B' },{ 'P','V' },
            //    { 'Q','H' },{ 'R','N' },{ 'S','C' },{ 'T','M' },
            //    { 'U','I' },{ 'V','Z' }, {'W','L' },{ 'X','Y' },
            //    { 'Y','J' },{ 'Z','K' },
            //};
            string output_string = "";
            for (int i = 0; i<plainText.Length; i++)
            {
                if (plainText[i] == ' ')
                {
                    output_string += " ";
                }
                else
                {

                    output_string += key[plainText[i] - 65];
                }
            }
            return output_string;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
            cipher = cipher.ToUpper(); 
            Dictionary<char, char> key = new Dictionary<char, char>();
            string output_s = "";
            //ETAOINSRHLDCUMFPGWYBVKXHQZ
            string freq_sorted = "ZQJXKVBYWGPFMUCDLHRSNIOATE";
            Dictionary<char, int> letter_freq = new Dictionary<char, int>();
            foreach (char ch in cipher)
            {
                if (!letter_freq.ContainsKey(ch))
                {
                    letter_freq.Add(ch, 1);
                }
                else
                {
                    letter_freq[ch]++;
                }
            }
            var sorted_letters = letter_freq.OrderBy(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            int l = 0;
            foreach (var x in sorted_letters)
            {
                //Console.WriteLine(x);
                key.Add(x.Key, freq_sorted[l]);
                l++;
            }
            var arr = key.OrderBy(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            foreach (var y in arr)
            {
                output_s += y.Key;
                //Console.WriteLine(y);
            }
            //output_s = output_s.ToLower();
            string f = Decrypt(cipher, output_s);
            f= f.ToLower();
            return f;
        }
    }
}
