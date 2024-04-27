using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public int[] SBox_Initialize()
        {
            int [] SBox = new int[256];
            for (int i=0; i< 256; i++ )
            {
                SBox[i] = i;
            }
            return SBox;
        }
        public int[] Key_array_initialize(string key)//test
        {
            int[] Key_Array = new int[256];
            int key_lenght = key.Length;
            int counter = 0;
            for (int i = 0; i < 256; i++)
            {
                Key_Array[i] = (int)key[counter];
                counter++;
                if (counter == key_lenght)
                    counter = 0;
            }
            return Key_Array;
        }
        public int[] Text_To_Corresponding_Asci(string text)
        {
            int[] Corresponding_Ascii = new int[text.Length];

            for (int i = 0; i < text.Length; i++)
            {
                Corresponding_Ascii[i] = (int)text[i];
            }
            return Corresponding_Ascii;
        }
        public string Ascii_to_corresponding_text(int[] arr)
        {
            string Resulted_String = "";
            foreach (int asciiValue in arr)
            {
                Resulted_String += (char)asciiValue;
            }

            return Resulted_String;
        }
        public static void Swap(ref int a, ref int b)
        {
            int temp = a;
            a = b;
            b = temp;
        }
        public int[] SBox_Permutate_key_stream(int[] SBox , int[] Key_Array , int Plain_txt_size)
        {
            int i = 0;
            int  j = 0;
            for ( i =0; i <256;i++)
            {
                j = (j + Key_Array[i] + SBox[i]) % 256;
                Swap(ref SBox[i], ref SBox[j]);
            }

            //stream Generation:-
             i = 0; j = 0;
            int[] key_stream = new int[Plain_txt_size];
             for(int k = 0; k< Plain_txt_size; k++)
             {
                i = (i + 1) % 256;
                j = (j + SBox[i]) % 256;
                Swap( ref SBox[i] ,ref SBox[j]);
                int tmp_index = (SBox[i] + SBox[j]) % 256;
                key_stream[k] = SBox[tmp_index];
             }

            return key_stream;
        }
        public int[] XOR(int[] Plain_txt , int[] key_stream)
        {
            int size = Plain_txt.Length;
            int[] result = new int[size];

            for(int i = 0; i < size; i++)
            {
                result[i] = Plain_txt[i] ^ key_stream[i];
            }

            return result;
        }
        static string HexToString(string hexString)
        {
            if (hexString.StartsWith("0x"))
            {
                hexString = hexString.Substring(2);
            }
            // Convert the hexadecimal string to a byte array
            byte[] bytes = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }

            // Convert the byte array to a string using ISO-8859-1 encoding
            string text = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);

            return text;
        }
        static string StringToHexString(string text)
        {
            string hexString = "0x";

            foreach (char c in text)
            {
                hexString += ((int)c).ToString("x");
            }

            return hexString;
        }
        /// <summary>
        /// Steps:-
        /// -------
        /// [1] initialize 2 arrays (sbox , key)
        /// [2] sbox[256] values[i] from 0 till 255
        /// [3] Kbox[256] = corresponding ascii of char of key string repeatedly until 256 element is filled
        /// [4] generating permutation in sbox by swapping 256 element in sbox based on calculation
        /// [5] generating key stream 
        /// [6] prepare plain text by convert it to list of ascii
        /// [7] c.t = p.t xor key_stream
        /// [8] convert c.t to actual text from ascii
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override string Encrypt(string plainText, string key)
        {
            bool hexa = false;
            if (plainText.StartsWith("0x") )
            {
                hexa = true;
                plainText = HexToString(plainText);
               
            }
            if (key.StartsWith("0x"))
            {
                hexa = true;
                key = HexToString(key);
            }
            //[1,2]
            int[] s_box = new int[256];
            s_box = SBox_Initialize();

            //[3]
            int[] k = new int[256];
            k = Key_array_initialize(key);

            //[4,5]
            int size_plain_txt = plainText.Length;
            int[] key_stream = new int[size_plain_txt];
            key_stream = SBox_Permutate_key_stream(s_box, k, size_plain_txt);

            //[6]
            int[] list_of_plain_Ascii = new int[size_plain_txt];
            list_of_plain_Ascii = Text_To_Corresponding_Asci(plainText);

            //[7]
            int[] list_of_cipher_txt = new int[size_plain_txt];
            list_of_cipher_txt = XOR(list_of_plain_Ascii, key_stream);

            //[8]
            string cipher_text = Ascii_to_corresponding_text(list_of_cipher_txt);


            if (hexa)
            {
                cipher_text = StringToHexString(cipher_text);
            }

            return cipher_text;
        }
        /// <summary>
        /// 
        ///  Steps:-
        /// -------
        /// [1] initialize 2 arrays (sbox , key)
        /// [2] sbox[256] values[i] from 0 till 255
        /// [3] Kbox[256] = corresponding ascii of char of key string repeatedly until 256 element is filled
        /// [4] generating permutation in sbox by swapping 256 element in sbox based on calculation
        /// [5] generating key stream 
        /// [6] prepare cipher text by convert it to list of ascii
        /// [7] p.t = c.t xor key_stream
        /// [8] convert p.t to actual text from ascii
        /// Pi = Ci XOR k
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override string Decrypt(string cipherText, string key)
        {
            bool hexa = false;
            if (cipherText.StartsWith("0x"))
            {
                hexa = true;
                cipherText = HexToString(cipherText);

            }
            if (key.StartsWith("0x"))
            {
                hexa = true;
                key = HexToString(key);
            }
            //[1,2]
            int[] s_box = new int[256];
            s_box = SBox_Initialize();

            //[3]
            int[] k = new int[256];
            k = Key_array_initialize(key);

            //[4,5]
            int size_cipher_txt = cipherText.Length;
            int[] key_stream = new int[size_cipher_txt];
            key_stream = SBox_Permutate_key_stream(s_box, k, size_cipher_txt);

            //[6]
            int[] list_of_cipher_Ascii = new int[size_cipher_txt];
            list_of_cipher_Ascii = Text_To_Corresponding_Asci(cipherText);

            //[7]
            int[] list_of_plain_txt = new int[size_cipher_txt];
            list_of_plain_txt = XOR(list_of_cipher_Ascii, key_stream);

            //[8]
            string plain_text = Ascii_to_corresponding_text(list_of_plain_txt);


            if (hexa)
            {
                plain_text = StringToHexString(plain_text);
            }

            return plain_text;
        }

       
    }
}
