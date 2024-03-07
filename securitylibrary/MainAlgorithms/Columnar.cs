using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        int Rows = -1;
        private void GetRows(string plainText,string cipherText,int currCipher,int parentPlainIndex = -1,int difference = -1)
        {
            int i = parentPlainIndex + 1;
            if (parentPlainIndex == -1)
                i = 0;
            bool flag = false;
            for(; i < plainText.Length; i++)
            {
                if (currCipher < cipherText.Length && plainText[i].Equals(cipherText[currCipher]))
                {
                    if (parentPlainIndex == -1)
                    {
                        flag = true;
                        GetRows(plainText, cipherText, currCipher + 1, i);
                        
                    }
                    else
                    {   
                        if(difference == -1 || difference == i - parentPlainIndex)
                        {
                            flag = true;
                            GetRows(plainText, cipherText, currCipher + 1, i, i - parentPlainIndex);
                           
                        }
                    }
                }
            }
            if (!flag)
            {
                Rows = Math.Max(Rows,currCipher);
            }
            
        }

        private char[,] GetMatrix(string plainText,string cipherText,int Rows,int Cols)
        {

            int ctr = 0;
            char[,] matrix = new char[Rows, Cols];
            for (int i = 0; i < Rows; i++)
            {
                for (int j = 0; j < Cols; j++)
                {
                    if (plainText.Length <= ctr)
                        break;
                    matrix[i, j] = plainText[ctr++];
                }
            }
            
          
            return matrix;
        }

        public List<int> Analyse(string plainText, string cipherText)
        {
            //#1 Get # of rows
            //#2 build matrix
            //#3 search for the start of the index
            //#4 increment position each time
            cipherText = cipherText.ToLower();
            GetRows(plainText, cipherText, 0);
            int Cols = (int)Math.Ceiling((double)plainText.Length / Rows * 1.0);

            char[,] matrix = GetMatrix(plainText, cipherText, Rows, Cols);

            if (cipherText.Length != Rows * Cols)
            {
                StringBuilder str = new StringBuilder();
                int length = Rows * Cols - plainText.Length;
                for (int i = 0; i < length; i++)
                    str.Append('x');
                cipherText = cipherText + str.ToString();
            }

            int[] arr = new int[Cols];
            int ans = 1;
            for (int cipherCtr = 0; cipherCtr < cipherText.Length; cipherCtr += Rows)
            {
                
                for (int i = 0; i < Cols; i++)
                {
                    bool isRightCol = true;
                    for (int j = 0; j < Rows; j++)
                    {
                        if (!matrix[j, i].Equals(cipherText[cipherCtr + j]))
                        {
                            isRightCol = false;
                            break;
                        }
                    }
                    if (isRightCol)
                    {
                        arr[i] = ans++;
                        break;
                    }
                }
                
            }
            
            List<int> key = new List<int>();
            for (int i = 0; i < Cols; i++)
                key.Add(arr[i]);
            

            return key;
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
