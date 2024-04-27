using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Numerics;
namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            //ct = m^e mod n 
             int n = p * q;
             int result = 1;
           
            for ( int i =0; i< e; i++)
            {
                result = (result* M)%n;

            }
              
             return result;
            
        }


        public int GetMultiplicativeInverse(int number, int baseN)
        {


            int divided = number;
            int divisor = baseN;

            int A1 = 1, A2 = 0, A3 = divisor;
            int B1 = 0, B2 = 1, B3 = divided;

            while (B3 != 0 && B3 != 1)
            {
                int Q = A3 / B3;

                int T1 = A1 - (Q * B1);
                int T2 = A2 - (Q * B2);
                int T3 = A3 - (Q * B3);

                A1 = B1;
                A2 = B2;
                A3 = B3;

                B1 = T1;
                B2 = T2;
                B3 = T3;
            }

            if (B3 == 0)
            {
                return -1;
            }
            else if (B3 == 1)
            {
                if (B2 < -1)
                {
                    do
                    {
                        B2 = B2 + divisor;
                    } while (B2 < 0);
                    return B2;
                }
                else
                {
                    return B2;
                }
            }
            return -1;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //m = c^d mod n
            //d = e^-1 mod totient
            int n = p * q;
            int totient = (p - 1) * (q - 1);
            int multi_inverse = GetMultiplicativeInverse(e, totient);
            int d = multi_inverse % totient;
            int result = 1;
            for (int i = 0; i < d; i++)
            {
                result = (result * C) % n;

            }
             return result;


        }
    }
}
