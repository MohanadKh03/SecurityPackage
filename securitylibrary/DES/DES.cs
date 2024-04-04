using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {


        static string[] Key = new string[17];
        static string[] C = new string[17], D = new string[17];

        static int[][] PC1 = {
            new int[]{57, 49, 41, 33, 25, 17, 9 },
            new int[]{1, 58, 50, 42, 34, 26, 18 },
            new int[]{10, 2, 59, 51, 43, 35, 27 },
            new int[]{19, 11, 3, 60, 52, 44, 36 },
            new int[]{63, 55, 47, 39, 31, 23, 15 },
            new int[]{7, 62, 54, 46, 38, 30, 22},
            new int[]{14, 6, 61, 53, 45, 37, 29 },
            new int[]{21, 13, 5, 28, 20, 12, 4 }
        };
        static int[][] PC2 = {
            new int[]{ 14, 17, 11, 24,  1,  5 },
            new int[]{  3, 28, 15,  6, 21, 10 },
            new int[]{ 23, 19, 12,  4, 26,  8 },
            new int[]{ 16,  7, 27, 20, 13,  2 },
            new int[]{ 41, 52, 31, 37, 47, 55 },
            new int[]{ 30, 40, 51, 45, 33, 48 },
            new int[]{ 44, 49, 39, 56, 34, 53 },
            new int[]{ 46, 42, 50, 36, 29, 32 }
        };

        static int[][] IP = {
            new int[]{ 58, 50, 42, 34, 26, 18, 10,  2 },
            new int[]{ 60, 52, 44, 36, 28, 20, 12,  4 },
            new int[]{ 62, 54, 46, 38, 30, 22, 14,  6 },
            new int[]{ 64, 56, 48, 40, 32, 24, 16,  8 },
            new int[]{ 57, 49, 41, 33, 25, 17,  9,  1 },
            new int[]{ 59, 51, 43, 35, 27, 19, 11,  3 },
            new int[]{ 61, 53, 45, 37, 29, 21, 13,  5 },
            new int[]{ 63, 55, 47, 39, 31, 23, 15,  7 }
        };


        static int[][] IPInverse = {
            new int[]{ 40,  8, 48, 16, 56, 24, 64, 32 },
            new int[]{ 39,  7, 47, 15, 55, 23, 63, 31 },
            new int[]{ 38,  6, 46, 14, 54, 22, 62, 30 },
            new int[]{ 37,  5, 45, 13, 53, 21, 61, 29 },
            new int[]{ 36,  4, 44, 12, 52, 20, 60, 28 },
            new int[]{ 35,  3, 43, 11, 51, 19, 59, 27 },
            new int[]{ 34,  2, 42, 10, 50, 18, 58, 26 },
            new int[]{ 33,  1, 41,  9, 49, 17, 57, 25 }
         };

        static int[][] Expansion = {
            new int[]{ 32,  1,  2,  3,  4,  5 },
            new int[]{  4,  5,  6,  7,  8,  9 },
            new int[]{  8,  9, 10, 11, 12, 13 },
            new int[]{ 12, 13, 14, 15, 16, 17 },
            new int[]{ 16, 17, 18, 19, 20, 21 },
            new int[]{ 20, 21, 22, 23, 24, 25 },
            new int[]{ 24, 25, 26, 27, 28, 29 },
            new int[]{ 28, 29, 30, 31, 32,  1 }
        };

        static int[][][] SBox = {
            new int[][]{},
            new int[][]{
                new int[] {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                new int[] {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                new int[] {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                new int[] {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
            },
            new int[][]{
                new int[]{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                new int[]{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                new int[] {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                new int[] {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            new int[][]{
                new int[]{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                new int[]{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                new int[]{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                new int[]{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
            },
            new int[][] {
                new int[] {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                new int[] {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                new int[] {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                new int[] {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
            },
            new int[][]{
                new int[] {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                new int[] {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                new int[] {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                new int[] {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
            },
            new int[][]{
                new int[] {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                new int[] {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                new int[] {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                new int[] {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
            },
            new int[][]{
                new int[]{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                new int[]{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                new int[]{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                new int[]{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
            },
            new int[][]{
                new int[]{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                new int[]{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                new int[] {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                new int[]{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
            }
        };

        static int[][] PTable = {
              new int[]{ 16,  7, 20, 21 },
              new int[]{ 29, 12, 28, 17 },
              new int[]{  1, 15, 23, 26 },
              new int[]{  5, 18, 31, 10 },
              new int[]{  2,  8, 24, 14 },
              new int[]{ 32, 27,  3,  9 },
              new int[]{ 19, 13, 30,  6 },
              new int[]{ 22, 11,  4, 25 }
        };

        static int[] RotationTable = { 0, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        private static string HexaToBinary(string Hexa)
        {
            StringBuilder binaryString = new StringBuilder();
            foreach (char hexChar in Hexa)
            {
                int intValue = Convert.ToInt32(hexChar.ToString(), 16);
                string binaryChar = Convert.ToString(intValue, 2).PadLeft(4, '0');
                binaryString.Append(binaryChar);
            }
            return binaryString.ToString();
        }

        private static string GetEquivalentPermutation(string BinaryKey, int[][] Table)
        {
            StringBuilder PermutationKey = new StringBuilder();
            for (int i = 0; i < Table.Length; i++)
            {
                for (int j = 0; j < Table[i].Length; j++)
                {
                    char x = BinaryKey[Table[i][j] - 1];
                    PermutationKey.Append(x);
                }
            }
            return PermutationKey.ToString();
        }
        private static string ShiftStringToLeftByNumber(string Binary, int Number)
        {

            string shiftedString = Binary.Substring(Number, Binary.Length - Number);
            for (int i = 0; i < Number; i++)
                shiftedString += Binary[i];
            return shiftedString;
        }
        private static void FillKeyHalves(string PermutationKey)
        {
            C[0] = PermutationKey.Substring(0, PermutationKey.Length / 2);
            D[0] = PermutationKey.Substring(PermutationKey.Length / 2, PermutationKey.Length / 2);

            for (int i = 1; i <= 16; i++)
            {
                C[i] = ShiftStringToLeftByNumber(C[i - 1], RotationTable[i]);
                D[i] = ShiftStringToLeftByNumber(D[i - 1], RotationTable[i]);
            }
        }
        private static void Generate16Keys()
        {
            int keyIndex = 1;
            while (keyIndex <= 16)
            {
                StringBuilder currKey = new StringBuilder();
                string CD = C[keyIndex] + D[keyIndex];
                int ctr = 0;
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        ctr++;
                        char bit;
                        int index = PC2[i][j] - 1;
                        bit = CD[index];
                        currKey.Append(bit);
                    }
                }
                Key[keyIndex] = currKey.ToString();
                keyIndex++;
            }
        }

        static void GenerateSubkeys(string HexaKey)
        {
            string BinaryKey = HexaToBinary(HexaKey);
            string PermutationKey = GetEquivalentPermutation(BinaryKey, PC1);
            FillKeyHalves(PermutationKey);
            Generate16Keys();
        }

        static string XORTwoStrings(string string1, string string2)
        {
            if (string1.Length != string2.Length)
                throw new Exception("Length of strings should be equal");
            int size = string1.Length;
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < size; i++)
            {
                if (string1[i] == string2[i])
                    output.Append('0');
                else
                    output.Append('1');
            }
            return output.ToString();
        }

        static int BinaryStringToInt(string BinaryString)
        {
            int result = 0;
            int power = 0;

            for (int i = BinaryString.Length - 1; i >= 0; i--)
            {
                int digit = BinaryString[i] - '0';
                if (digit == 1)
                    result += (int)Math.Pow(2, power);

                power++;
            }
            return result;
        }

        private static string BinaryStringToHexa(string BinaryString)
        {
            StringBuilder hexString = new StringBuilder();

            // Process the binary string in groups of 4 bits
            for (int i = 0; i < BinaryString.Length; i += 4)
            {
                string FourBinaryBits = BinaryString.Substring(i, 4);

                int DecimalValue = Convert.ToInt32(FourBinaryBits, 2);

                hexString.Append(DecimalValue.ToString("X"));
            }

            return hexString.ToString();
        }


        static string IntToBinaryString(int value)
        {
            Stack<char> c = new Stack<char>();
            while (value > 0)
            {
                int remainder = value % 2;

                c.Push((char)(remainder + '0'));

                value /= 2;
            }
            string ans = "";
            while (c.Count != 0)
            {
                ans += c.Pop();
            }
            return ans;
        }
        static string SubBox(string SBoxInput, int SBoxNum)
        {
            string StringRow = SBoxInput[0].ToString() + SBoxInput[SBoxInput.Length - 1].ToString();
            string StringCol = SBoxInput.Substring(1, 4);
            int Row = BinaryStringToInt(StringRow);
            int Col = BinaryStringToInt(StringCol);
            int SBoxValue = SBox[SBoxNum][Row][Col];
            return IntToBinaryString(SBoxValue);
        }
        static string GetSBoxValue(string SBoxInput)
        {
            int SBoxNum = 1;
            string SBoxTotalOutput = "";
            for (int i = 0; i < 48; i += 6)
            {
                string SubOutput = SBoxInput.Substring(i, 6);
                string BoxOutput = SubBox(SubOutput, SBoxNum);
                while (BoxOutput.Length != 4)
                {
                    BoxOutput = BoxOutput.Insert(0, "0");
                }
                SBoxTotalOutput += BoxOutput;
                SBoxNum++;
            }
            return SBoxTotalOutput;
        }
        private static string F(string Right, string Key)
        {
            string ExpandedRight = GetEquivalentPermutation(Right, Expansion);
            string XOROutput = XORTwoStrings(ExpandedRight, Key);

            string SBoxTotalOutput = GetSBoxValue(XOROutput);

            string PTableOutput = GetEquivalentPermutation(SBoxTotalOutput, PTable);

            return PTableOutput;
        }


        public override string Decrypt(string cipherText, string key)
        {
            key = key.Substring(2);
            cipherText = cipherText.Substring(2);
            string BinaryCipherText = HexaToBinary(cipherText);
            GenerateSubkeys(key);
            string PermutationCipherText = GetEquivalentPermutation(BinaryCipherText, IP);
            string Left, Right;

            Left = PermutationCipherText.Substring(0, PermutationCipherText.Length / 2);
            Right = PermutationCipherText.Substring(PermutationCipherText.Length / 2, PermutationCipherText.Length / 2);

            for (int i = 16; i >= 1; i--)
            {
                string PreviousR = Right;
                Right = F(Right, Key[i]);
                Right = XORTwoStrings(Right, Left);
                Left = PreviousR;
            }
            string ReversedConcatenation = Right + Left;
            string FinalPermutation = GetEquivalentPermutation(ReversedConcatenation, IPInverse); 

            return "0x" + BinaryStringToHexa(FinalPermutation);
        }

        public override string Encrypt(string plainText, string key)
        {
            key = key.Substring(2);//remove the '0x' in hexa string
            plainText = plainText.Substring(2);
            string BinaryPlainText = HexaToBinary(plainText);
            GenerateSubkeys(key);
            string PermutationPlainText = GetEquivalentPermutation(BinaryPlainText, IP);

            string Left, Right;
            Left = PermutationPlainText.Substring(0, PermutationPlainText.Length / 2);
            Right = PermutationPlainText.Substring(PermutationPlainText.Length / 2, PermutationPlainText.Length / 2);
            for (int i = 1; i <= 16; i++)
            {
                string PreviousR = Right;
                Right = F(Right, Key[i]);
                Right = XORTwoStrings(Right, Left);
                Left = PreviousR;
            }
            string ReversedConcatenation = Right + Left;
            string FinalPermutation = GetEquivalentPermutation(ReversedConcatenation, IPInverse);
            return "0x" + BinaryStringToHexa(FinalPermutation);
        }
    }
}