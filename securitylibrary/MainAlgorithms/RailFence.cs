using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {

            int max_possible_key = (int)Math.Ceiling((double)(plainText.Length + 1) / 2);
            string decryptedPlainText;
            int key = 1;
            for (; key <= max_possible_key; key++)
            {
                decryptedPlainText = Decrypt(cipherText, key).ToLower();


                if (decryptedPlainText.Equals(plainText.ToLower()))
                {

                    break;

                }
            }
            return key;
         
        }


        static char[,] Create_DMatrix(string text, int key)
        {
            int col_num = (int)Math.Ceiling((double)text.Length / key);
            char[,] matrix = new char[key, col_num];
            int index = 0;

            for (int row = 0; row < key; row++)
            {
                for (int col = 0; col < col_num; col++)
                {
                    if (index < text.Length)
                    {
                        matrix[row, col] = text[index];
                        index++;
                    }

                }
                if (row == 0 && text.Length % key != 0)
                {
                   
                    col_num--;
                }
            }
            return matrix;
        }


        public string Decrypt(string cipherText, int key)
        {
            int col_num = (int)Math.Ceiling((double)cipherText.Length / key);
            char[,] matrix = Create_DMatrix(cipherText, key);
            int index = 0;

            StringBuilder result = new StringBuilder();
            for (int col = 0; col < col_num; col++)
            {
                for (int row = 0; row < key; row++)
                {
                    if (matrix[row, col] != '\0') 
                    {
                        result.Append(matrix[row, col]);
                        index++;
                    }
                }
            }

            return result.ToString().ToLower();




        }

        static char[,] Create_CMatrix(string text, int key)
        {
            int column_num = (int)Math.Ceiling((double)text.Length / key);
            char[,] matrix = new char[key, column_num];

            int index = 0;
            for (int col = 0; col < column_num; col++)
            {
                for (int row = 0; row < key; row++)
                {
                    if (index < text.Length)
                    {
                        matrix[row, col] = text[index];
                        index++;
                    }
                    
                }
            }
            return matrix;
        }


      
        public string Encrypt(string plainText, int key)
        {


            int col_num = (int)Math.Ceiling((double)plainText.Length / key);
            char[,] matrix = Create_CMatrix(plainText, key);

           
            StringBuilder result = new StringBuilder();
            for (int row = 0; row < key; row++)
            {
                for (int col = 0; col < col_num; col++)
                {
                    result.Append(matrix[row, col]);
                }
            }

            return result.ToString();
        }
    }
}





   
