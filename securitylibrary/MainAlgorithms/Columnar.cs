using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int num_of_columns = key.Count;
            int num_of_rows = (cipherText.Length + num_of_columns - 1) / num_of_columns;
            char[,] plain = new char[num_of_rows, num_of_columns];
            int enteredcol = 0;
            int index_of_CT = 0;
            
             int numOfXs = num_of_rows * num_of_columns - cipherText.Length; 
             int idxOfColumnWithX = num_of_columns - numOfXs;  
             
            while (enteredcol < num_of_columns)
            {
                for (int i = 0; i < num_of_columns; i++)
                {
                    if (key[i] == enteredcol + 1)
                    {
                        for (int row = 0; row < num_of_rows; ++row)
                        {

                            if (row == num_of_rows - 1 && key[i] > idxOfColumnWithX)
                                plain[row, i] = 'x';
                            else
                            {
                                plain[row, i] = cipherText[index_of_CT];
                                index_of_CT++;
                            }   
                        }
                        enteredcol++;  
                        //throw new NotImplementedException();
                    }
                }
            }
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < num_of_rows; i++)
            {
                for (int j = 0; j < num_of_columns; j++)
                {

                    result.Append(plain[i, j]);
                }
            }
            return result.ToString();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int num_of_columns = key.Count;
            int num_of_rows = (plainText.Length + num_of_columns - 1) / num_of_columns;
            char[,] cipher = new char[num_of_rows, num_of_columns];
            //fill 2d array
            int index_of_PT = 0;
            for (int i = 0; i < num_of_rows; i++)
            {
                for (int j = 0; j < num_of_columns; j++)
                {
                    if (index_of_PT < plainText.Length)
                    {
                        cipher[i, j] = plainText[index_of_PT];
                        index_of_PT++;
                    }
                    else
                    {
                        cipher[i, j] = 'x';
                    }
                }
            }
            int printedCols = 0;
            StringBuilder result = new StringBuilder();
            while (printedCols <num_of_columns)
                for (int i = 0; i < num_of_columns; i++)
                    if (key[i] == printedCols + 1)
                    {

                        for (int row = 0; row < num_of_rows; ++row)
                            result.Append(cipher[row, i]);
                        printedCols++;
                    }
            return result.ToString();
            // throw new NotImplementedException();
        }
    }
}
