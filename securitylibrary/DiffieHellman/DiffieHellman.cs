using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public int ModPow(int baseNumber, int exponent, int modulus)
        {
            if (modulus == 0)
                return 0;

            int pow = 1;
            for (int i = 0; i < exponent; i++)
            {
                pow = (pow * baseNumber) % modulus;
            }
            return pow;
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            int publicKeyA = ModPow(alpha, xa, q);
            int publicKeyB = ModPow(alpha, xb, q);

            int secretKeyA = ModPow(publicKeyB, xa, q);
            int secretKeyB = ModPow(publicKeyA, xb, q);

            List<int> keys = new List<int>() { secretKeyA , secretKeyB};

            return keys;
        }
    }
}
