using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net.Http.Headers;
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
        //****helper function****//

        //////ممكن يكون في مشكلة في حتة اني اجيب السايز بتاع الليست ال 2 دايمنشن هتشيك عليه/////
        // for 2x2Matrix:-
        //----------------
        int get_positive(int n)
        {
            /*
                    int result;
                    while (n < 0)
                    {
                        n += 26;
                    }
                    result = n;
            */
            return (n % 26 + 26) % 26;
        }
        int multiplicativeInverseOfB(int det)
        {
            int j= 0;
            for (int i = 1; i <= 26; i++)
            {
                int x = (det * i) - ((int)(det * i / 26) * 26);
                if (x == 1)
                {
                    j = i;
                    break;
                }
            }

            return j;  
        }
        
        int determinant2x2(List<int> matrix2x2)
        {
            int end = 3;
            int start = 0;
            int res = (matrix2x2[start] * matrix2x2[end]) - ((matrix2x2[start + 1]) * (matrix2x2[end - 1]));
            if (res < 0)
            {
                res = get_positive(res);
            }
            return res;
        }
        List<int> adjugate2x2(List<int> matrix2x2)
        {
            List<int> res =new List <int> (4);
            res.Insert(0 , matrix2x2[3])  ;
            res.Insert(1 , -matrix2x2[1]) ;
            res.Insert(2 , -matrix2x2[2]) ;
            res.Insert(3 , matrix2x2[0]) ;

            return res;
        }

        List<int> inverse2x2(List<int> adjugatedMatrixMod26  , int multiplicative_inverse_det)
        {
            List<int> inversedKey = new List<int> (4);
           
           
            for (int i = 0; i < 4; i++)
            {
                inversedKey.Add( ((int)multiplicative_inverse_det * adjugatedMatrixMod26[i]) % 26)  ;
            }
            return inversedKey;
        }
        //-----------------------------------------------------------------------//
        //shapes [matrix - list]:-
        //------------------------
        List<List<int>> matrixShape(List<int> matList)
        {
            int dim = (int)Math.Sqrt(matList.Count); // #of rows
            List<List<int>> myMat = new List<List<int>> (dim);

            // Initialize the inner lists
            for (int i = 0; i < dim; i++)
            {
                myMat.Add(new List<int>());
            }
            int val;
            
            for (int i = 0; i < dim; i++)
            {
                for (int j = 0; j < dim; j++)
                {
                    val = matList[dim * i + j];
                    myMat[i].Add (val);
                }
            }
            return myMat;
        }

        List<int> matrixListShape(List<List<int>> mat)
        {
            int size = mat.Count;     // get numb of rows
            List<int> list = new List<int>();
 
            int n;
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    n = mat[i][j];
                    list.Add(n);
                }
            }

            return list;
        }

        List<List<int>> matrix_transpose(List<List<int>> m)
        {
            int dim = m.Count;
            List<List<int>> T = new List<List<int>>(dim);

            for (int i = 0; i < dim; i++)
            {
                T.Add(new List<int>(dim));
            }

            for (int i = 0; i < dim; i++)
            {
                for (int j = 0; j < dim; j++)
                {
                    T[i].Add (m[j][i]);
                }
            }
            return T;
        }
        //-----------------------------------------------------------------------//
        //for 3x3Matrix:-
        //---------------


        /// <summary>
        ///     //steps:
                //------
                //[1] put list in form of 3x3 matrix
                //[2] first element *(det2x2 of element by eliminate row and col) - second element(det2x2) + third ele*(det2x2)
                //[3] if -ve -> add 26  handle 
        /// </summary>
        /// <param name="v"></param>
        /// <returns></returns>
        int determinant3x3(List<int> v)
        {
            //1- put list in form of 3x3 matrix
            int dim = (int)Math.Sqrt(v.Count);
            List<List<int>> V_matrix = new List<List <int>> (dim) ;

            // Initialize the inner lists
            for (int i = 0; i < dim; i++)
            {
                V_matrix.Add(new List<int>(dim));
            }
            V_matrix = matrixShape(v);

            //2-
            int ans;

            int first_element = V_matrix[0][0];
            int middle_element = V_matrix[0][1];
            int last_element = V_matrix[0][2];

            List<int> dm1 = new List<int> { V_matrix[1][1], V_matrix[1][2], V_matrix[2][1], V_matrix[2][2] };
            List<int> dm2 = new List<int> { V_matrix[1][0], V_matrix[1][2], V_matrix[2][0], V_matrix[2][2] };
            List<int> dm3 = new List<int> { V_matrix[1][0], V_matrix[1][1], V_matrix[2][0], V_matrix[2][1] };
            int d1 = determinant2x2(dm1);
            int d2 = determinant2x2(dm2);
            int d3 = determinant2x2(dm3);
            ans = first_element * d1 - middle_element * d2 + last_element * d3;

            //3-
            if (ans < 0)
            {
                ans = get_positive(ans);
            }

            return ans;
        }

        List<List<int>> determinant_each_element_mod26 (List<int> key)
        {
            int dim = (int)Math.Sqrt(key.Count);
            int var;
            List<List<int>> res = new List<List<int>> (dim);
            List<List<int>> key_matrix = new List<List<int>>(dim);

            for (int i = 0; i < dim; i++)
            {
                res.Add(new List<int>(dim));
                key_matrix.Add(new List<int>(dim));
            }

            key_matrix = matrixShape(key);
            for (int i = 0; i < dim; i++)
            {
                for (int j = 0; j < dim; j++)
                {
                    int i1 = (i + 1) % dim;
                    int j1 = (j + 1) % dim;
                    int i2 = (i + 2) % dim;
                    int j2 = (j + 2) % dim;

                    var = key_matrix[i1][j1] * key_matrix[i2][j2] - key_matrix[i1][j2] * key_matrix[i2][j1];
                    if ((i == 0 && j == 1) || (i == 1 && j == 0) || (i == 1 && j == 2) || (i == 2 && j == 1))
                    {
                        var *= -1;
                    }
                    if (var < 0)
                    {
                        var = get_positive(var);
                    }
                    res[i].Add(var % 26);
                }
            }
            return res;
        }
        List<List<int>> inverse3x3(List<int> l)
        {
            //steps:
            //------
            // rule (K[i][j] ^-1)= (b* (-1 ^i+j) * (D[i][j] mod 26 )) mod 26
            //[1] find b
            //[2] var = (get determinant of[i][j]) % 26
            //[3] k^-1[i][j] =( b * var ) % 26   have 2 cases : (a) if num +ve (b) if num -ve
            //[4] after matrix is done transpose it
            //-----------------------------------------------------------------------------------

            //1-
            int det = determinant3x3(l);
            if (det == 0)
            {
                throw new NotImplementedException(); // no inverse
            }
            int b = multiplicativeInverseOfB(det);

            //2- 
            int var;
            int dim = (int)Math.Sqrt(l.Count);
            List<List<int>> matrix = new List<List<int>>(dim);

            // Initialize the inner lists
            for (int i = 0; i < dim; i++)
            {
                matrix.Add(new List<int>(dim));
            }
            matrix = matrixShape(l);

            List<List<int>> inversed = new List<List<int>>(dim);
            // Initialize the inner lists
            for (int i = 0; i < dim; i++)
            {
                inversed.Add(new List<int>(dim));
            }

            for (int i = 0; i < dim; i++)
            {
                for (int j = 0; j < dim; j++)
                {
                    int i1 = (i + 1) % dim;
                    int j1 = (j + 1) % dim;
                    int i2 = (i + 2) % dim;
                    int j2 = (j + 2) % dim;

                    var = matrix[i1][j1] * matrix[i2][j2] - matrix[i1][j2] * matrix[i2][j1];
                    if ((i == 0 && j == 1) || (i == 1 && j == 0) || (i == 1 && j == 2) || (i == 2 && j == 1))
                    {
                        var *= -1;
                    }
                    var = var % 26;
                    //3-
                    inversed[i].ElementAt(j).Equals(( b * (int)Math.Pow(-1, i + j) * var ));
                    inversed[i].ElementAt(j).Equals( (inversed[i][j] % 26 + 26) % 26);
                }
            }

            //4-
            inversed = matrix_transpose(inversed);
            return inversed;
        }


        //----------------------------------------------------------------------//
        

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
                List <int> v = new List <int> (m);
                for (int i = 0; i < m; i++)
                {
                    v.Add(plainText.ElementAt(count));
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

        /// <summary>
        /// 
        /// //steps:
        /// // plain = ( k^-1 * ciphered txt ) mod 26 //
        /// // check if (key 2x2 or 3x3 ):
        /// // [1] if (2x2):
        /// //   * case(if det == 0)  no inverse no decrypt
        /// //   * multiplicative_inverse(determinant) mod 26
        /// //   * adjugate(key) mod 26 
        /// //   * key_inverse = multiplicative_inverse(determinant) * adjugate(key)   % 26
        /// //   * call Encrypt(key_inversed , cipher text ) will get plain text
        /// //
        /// // [2] if (3x3):
        /// //   * case(if det == 0)  no inverse no decrypt
        /// //   * multiplicative_inverse(determinant) mod 26
        /// //   * adjugate(key) mod 26 
        /// //   * key_inverse = multiplicative_inverse(determinant) * (-1)^i+j *  Dij mod 26
        /// //   * call Encrypt(key_inversed , cipher text ) will get plain text
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int dim_of_key = (int)Math.Sqrt(key.Count);
           
           
            List<int> ans = new List<int>();
          
            if (dim_of_key == 2) //mat2x2
            {
                int det = determinant2x2(key);
                if (det == 0 )
                {
                    throw new Exception();
                }
                det = det % 26;
                int b = multiplicativeInverseOfB(det);
                if (b == 0)
                {
                    throw new Exception();
                }
                List<int> adjugate = new List<int>();
                adjugate = adjugate2x2(key);

                for (int i = 0; i< dim_of_key *2; i++)
                {
                    if (adjugate[i] < 0)
                    {
                        adjugate[i] = get_positive(adjugate[i]);
                    }
                    adjugate[i] = adjugate[i] % 26;
                }
                List<int> inversed2x2_key = new List<int>();
                inversed2x2_key=  inverse2x2(adjugate ,b );

                int size = cipherText.Count;
                List<int> plain_txt = new List<int>(size);
                plain_txt = Encrypt(cipherText, inversed2x2_key);
                return plain_txt;
            }
            else if (dim_of_key == 3) 
            {
                int det = determinant3x3(key);
                if (det == 0) // no inverse no decrypt
                {
                    throw new Exception();
                }
                det = det % 26;
                int b = multiplicativeInverseOfB(det);
                List<List<int>> determinant_Matrix = new List<List<int>>(dim_of_key);
                List<List<int>> inversed3x3_key = new List<List<int>>();
                // Initialize the inner lists
                for (int i = 0; i < dim_of_key; i++)
                {
                    determinant_Matrix.Add(new List<int>(dim_of_key));
                    inversed3x3_key.Add(new List<int>(dim_of_key));
                }

                determinant_Matrix = determinant_each_element_mod26(key);
                int var;
               
                for (int i = 0; i < dim_of_key; i++)
                {
                    for (int j = 0; j < dim_of_key; j++)
                    {
                        var = b *(int) Math.Pow(-1, i + j)  * determinant_Matrix[i][j];
                        if (var < 0)
                        {
                            var = get_positive(var);
                        }
                        inversed3x3_key[i].Add(var % 26);
                    }
                }

                int size = cipherText.Count;
                inversed3x3_key = matrix_transpose(inversed3x3_key);
                List<int> key_list = new List<int>(dim_of_key*dim_of_key);
                key_list = matrixListShape(inversed3x3_key);
                List<int> plain_txt = new List<int>(size);

                plain_txt = Encrypt(cipherText, key_list);
                return plain_txt;
            }
            else
            {
                throw new Exception();
            }
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int[]> possibleKey = new List<int[]>();
            List<int> cip = new List<int>();
            int[] arr = new int[4];
            for (int i = 0; i <= 25; i++)
            {
                for (int j = 0; j <= 25; j++)
                {
                    for (int k = 0; k <= 25; k++)
                    {
                        for (int l = 0; l <= 25; l++)
                        {
                            arr[0] = i;
                            arr[1] = j;
                            arr[2] = k;
                            arr[3] = l;
                            List<int> key = arr.ToList();
       
                            cip = Encrypt(plainText, key);
                            bool p = Enumerable.SequenceEqual(cip, cipherText);
                            if (p)
                                return key;
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int dim_of_key = 3;
            int det = determinant3x3(plain3);
            if (det == 0) // no inverse no decrypt
            {
                throw new Exception();
            }
            det = det % 26;
            int b = multiplicativeInverseOfB(det);
            List<List<int>> determinant_Matrix = new List<List<int>>(dim_of_key);
            List<List<int>> inversed3x3_plain = new List<List<int>>();
            // Initialize the inner lists
            for (int i = 0; i < dim_of_key; i++)
            {
                determinant_Matrix.Add(new List<int>(dim_of_key));
                inversed3x3_plain.Add(new List<int>(dim_of_key));
            }

            determinant_Matrix = determinant_each_element_mod26(plain3);
            int var;
               
            for (int i = 0; i < dim_of_key; i++)
            {
                for (int j = 0; j < dim_of_key; j++)
                {
                    var = b *(int) Math.Pow(-1, i + j)  * determinant_Matrix[i][j];
                    if (var < 0)
                    {
                        var = get_positive(var);
                    }
                    inversed3x3_plain[i].Add(var % 26);
                }
            }

           // int size = cipherText.Count;
            inversed3x3_plain = matrix_transpose(inversed3x3_plain);
            List<int> plain_list = new List<int>(dim_of_key*dim_of_key);
            plain_list = matrixListShape(inversed3x3_plain);
            List<int> key = new List<int>();

            key = Encrypt(matrixListShape( matrix_transpose(matrixShape( cipher3))), plain_list);
            return key;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
