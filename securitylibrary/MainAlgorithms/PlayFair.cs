using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
            
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        static string playfair_Cipher(string key, string plainText)
        {
            string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            //throw new NotImplementedException();
            key = key.ToUpper();
            key = key.Replace(" ", "");
            plainText = plainText.ToUpper();
            plainText = plainText.Replace(" ", "");
            string output_string = "";
            Dictionary<string, (int, int)> coordinates = new Dictionary<string, (int, int)>();
            int row = 0, col = 0;
            string[,] matrix = new string[5, 5];
            List<string> arr = new List<string>();
            for (int i = 0; i < plainText.Length; i++)
            {
                if (i % 2 == 0)
                {
                    string y = "";
                    if (i + 1 >= plainText.Length)
                    {
                        y += plainText[i];
                        y += 'X';
                    }
                    else
                    {
                        if (plainText[i] == plainText[i + 1])
                        {
                            plainText = plainText.Substring(0, i + 1) + 'X' + plainText.Substring(i + 1);
                        }
                        y += plainText[i];
                        y += plainText[i + 1];

                    }
                    arr.Add(y);
                }
            }
            for (int i = 0; i < key.Length; i++)
            {
                string x = "";
                if (key[i] == 'I' || key[i] == 'J')
                {
                    x = "IJ";
                }
                else
                {
                    x += key[i];
                }
                if (!coordinates.ContainsKey(x))
                {

                    coordinates.Add(x, (row, col));
                    matrix[row, col] = x;

                    col++;
                    if (col > 4)
                    {
                        row++;
                        col = 0;
                    }
                }
            }
            for (int i = 0; i < alpha.Length; i++)
            {
                string x = "";
                if (alpha[i] == 'I' || alpha[i] == 'J')
                {
                    x = "IJ";
                }
                else
                {
                    x += alpha[i];
                }
                if (!coordinates.ContainsKey(x))
                {

                    coordinates.Add(x, (row, col));
                    matrix[row, col] = x;
                    col++;
                    if (col > 4)
                    {
                        row++;
                        col = 0;
                    }
                }
            }

            foreach (string x in arr)
            {
                string first = "";
                string second = "";
                first += x[0];
                second += x[1];
                if (first == "I")
                {
                    first += "J";
                }
                else if (first == "J")
                {
                    first = "";
                    first += "I";
                    first += "J";
                }
                if (second == "I")
                {
                    second += "J";
                }
                else if (second == "J")
                {
                    second = "";
                    second += "I";
                    second += "J";
                }
                int r1, r2, c1, c2;
                r1 = coordinates[first].Item1;
                c1 = coordinates[first].Item2;
                r2 = coordinates[second].Item1;
                c2 = coordinates[second].Item2;
                string randomchar = "I";
                if (r1 == r2)
                {
                    if (matrix[r1, (c1 + 1) % 5] == "IJ")
                    {
                        output_string += randomchar;
                        output_string += matrix[r2, (c2 + 1) % 5];
                    }
                    else if (matrix[r2, (c2 + 1) % 5] == "IJ")
                    {
                        output_string += matrix[r1, (c1 + 1) % 5];
                        output_string += randomchar;

                    }
                    else
                    {
                        output_string += matrix[r1, (c1 + 1) % 5];
                        output_string += matrix[r2, (c2 + 1) % 5];
                    }
                }
                else if (c1 == c2)
                {
                    if (matrix[(r1 + 1) % 5, c1] == "IJ")
                    {
                        output_string += randomchar;
                        output_string += matrix[(r2 + 1) % 5, c1];
                    }
                    else if (matrix[(r2 + 1) % 5, c2] == "IJ")
                    {
                        output_string += matrix[(r1 + 1) % 5, c1];
                        output_string += randomchar;

                    }
                    else
                    {
                        output_string += matrix[(r1 + 1) % 5, c1];
                        output_string += matrix[(r2 + 1) % 5, c2];
                    }

                }
                else
                {
                    if (matrix[r1, c2] == "IJ")
                    {
                        output_string += randomchar;
                        output_string += matrix[r2, c1];
                    }
                    else if (matrix[r2, c1] == "IJ")
                    {
                        output_string += matrix[r1, c2];
                        output_string += randomchar;

                    }
                    else
                    {
                        output_string += matrix[r1, c2];
                        output_string += matrix[r2, c1];
                    }
                }
            }
            return output_string;
        }

         static int Mod(int a, int b)
         {
             return (a % b + b) % b;
         }

        static string playfair_Decipher(string key, string encryptedText)
        {
            string alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            key = key.ToUpper();
            key = key.Replace(" ", "");
            encryptedText = encryptedText.ToUpper();
            encryptedText = encryptedText.Replace(" ", "");
            string output_string = "";
            Dictionary<string, (int, int)> coordinates = new Dictionary<string, (int, int)>();
            int row = 0, col = 0;
            string[,] matrix = new string[5, 5];
            List<string> arr = new List<string>();
            for (int i = 0; i < encryptedText.Length; i++)
            {
                if (i % 2 == 0)
                {
                    string y = "";
                    y += encryptedText[i];
                    y += encryptedText[i + 1];
                    arr.Add(y);
                }

            }
            for (int i = 0; i < key.Length; i++)
            {
                string x = "";
                if (key[i] == 'I' || key[i] == 'J')
                {
                    x = "I";
                }
                else
                {
                    x += key[i];
                }
                if (!coordinates.ContainsKey(x))
                {
                    coordinates.Add(x, (row, col));
                    matrix[row, col] = x;
                    col++;
                    if (col > 4)
                    {
                        row++;
                        col = 0;
                    }
                }
            }
            for (int i = 0; i < alpha.Length; i++)
            {
                string x = "";
                if (alpha[i] == 'I' || alpha[i] == 'J')
                {
                    x = "I";
                }
                else
                {
                    x += alpha[i];
                }
                if (!coordinates.ContainsKey(x))
                {
                    coordinates.Add(x, (row, col));
                    matrix[row, col] = x;
                    col++;
                    if (col > 4)
                    {
                        row++;
                        col = 0;
                    }
                }
            }

            //int counter = 0;
            foreach (string x in arr)
            {
                string first = "";
                string second = "";
                first += x[0];
                second += x[1];
                /*if (second.Equals ("X"))
                {
                    counter++;
                }*/
                int r1, r2, c1, c2;
                r1 = coordinates[first].Item1;
                c1 = coordinates[first].Item2;
                r2 = coordinates[second].Item1;
                c2 = coordinates[second].Item2;

                if (r1 == r2)
                {
                    output_string += matrix[r1, Mod((c1 - 1), 5)];
                    output_string += matrix[r2, Mod((c2 - 1), 5)];
                }
                else if (c1 == c2)
                {
                    output_string += matrix[Mod((r1 - 1), 5), c1];
                    output_string += matrix[Mod((r2 - 1), 5), c2];
                }
                else
                {
                    output_string += matrix[r1, c2];
                    output_string += matrix[r2, c1];
                }
            }
            for (int i = 0; i < output_string.Length - 2; i++)
            {
                if (output_string[i + 2] == output_string[i] && output_string[i + 1] == 'X')
                {
                    output_string = output_string.Remove(i + 1, 1);
                }
            }

            if (output_string.EndsWith("X"))
            {
                output_string = output_string.Substring(0, output_string.Length - 1);
            }

            output_string = output_string.ToLower();

            
            return output_string;
        }



        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            return playfair_Decipher(key,cipherText);
        }

        

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            return playfair_Cipher(key, plainText);

        }
    }
}
