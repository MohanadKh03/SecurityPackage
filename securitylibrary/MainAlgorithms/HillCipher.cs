using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int plainTxtSize = plainText.Count;
            int keySize = key.Count;
            List<int> cipherTxt = new List<int> ();
            
            int count = 0;
            int index = 0;
            int n = plainTxtSize;

            int m =(int) Math.Sqrt(keySize);
            while (n > 0)
            {
                List <int> v = new List <int> ();
                for (int i = 0; i < m; i++)
                {
                    v.Add(plainText[count]);
                    count++;
                }
                // matrix element multiply
                for (int i = 0; i < m; i++)
                {
                    int k = 0;
                    int res = 0;
                    for (int j = 0; j < m; j++)
                    {
                        res += key[i * m + j] * v[k];
                        k++;
                    }
                    cipherTxt.Add(res % 26);
                    index++;
                }
                n-=m;
            }

            return cipherTxt;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
