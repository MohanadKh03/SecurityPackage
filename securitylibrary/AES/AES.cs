using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        enum Algorithm
        {
            ENCRYPT, DECRYPT
        };

        static string[] RoundKey = new string[11];//each key 4 bytes from left to right .. each row 8 digits
        static string[] Word = new string[44];
        static string[] RoundConstant =
        {
             "00" ,"01","02","04","08","10","20","40","80","1B","36"
        };

        static string[] MixColsTable =
        {
            "02030101",
            "01020301",
            "01010203",
            "03010102",
        };
        static string[] MixColsTableInverse =
        {
            "0E0B0D09",
            "090E0B0D",
            "0D090E0B",
            "0B0D090E"
        };

        static Dictionary<KeyValuePair<string, string>, string>
            ForwardHexaSBox = new Dictionary<KeyValuePair<string, string>, string>();
        static Dictionary<KeyValuePair<string, string>, string>
            InverseHexaSBox = new Dictionary<KeyValuePair<string, string>, string>();
        void InitializeSBoxes()
        {
            MakeForwardSBox();
            MakeInverseSBox();
        }

        private void MakeForwardSBox()
        {
            byte[] SBox =
            {
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
            };
            char prefix = '0';
            char currI = '0';
            int ctr = 0;
            while (currI != ('F' + 1))
            {
                char currJ = '0';
                while (currJ != ('F' + 1))
                {
                    KeyValuePair<string, string> pair = new KeyValuePair<string, string>(currI.ToString() + prefix.ToString(), prefix.ToString() + currJ.ToString());
                    string value = SBox[ctr].ToString("X").ToUpper();
                    if (value.Length != 2)
                    {
                        value = "0" + value;
                    }
                    ForwardHexaSBox.Add(pair, value);
                    if (currJ.Equals('9'))
                        currJ = 'A';
                    else
                        currJ++;
                    ctr++;
                }
                if (currI.Equals('9'))
                    currI = 'A';
                else
                    currI++;
            }
        }

        private void MakeInverseSBox()
        {
            byte[] SBoxInverse =
           {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
            };
            char prefix = '0';
            char currI = '0';
            int ctr = 0;
            while (currI != ('F' + 1))
            {
                char currJ = '0';
                while (currJ != ('F' + 1))
                {
                    KeyValuePair<string, string> pair = new KeyValuePair<string, string>(currI.ToString() + prefix.ToString(), prefix.ToString() + currJ.ToString());
                    string value = SBoxInverse[ctr].ToString("X").ToUpper();
                    if (value.Length != 2)
                    {
                        value = "0" + value;
                    }
                    InverseHexaSBox.Add(pair, value);
                    if (currJ.Equals('9'))
                        currJ = 'A';
                    else
                        currJ++;
                    ctr++;
                }
                if (currI.Equals('9'))
                    currI = 'A';
                else
                    currI++;
            }
        }

        public AES()
        {
            ForwardHexaSBox.Clear();
            InverseHexaSBox.Clear();
            InitializeSBoxes();
        }

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
        private static string ShiftStringToLeftByNumber(string Text, int Number)
        {

            string shiftedString = Text.Substring(Number, Text.Length - Number);
            for (int i = 0; i < Number; i++)
                shiftedString += Text[i];
            return shiftedString;
        }

        private static string ShiftLefBitwiseOperator(string BinaryText, int Number)
        {
            string shiftedString = BinaryText.Substring(Number);
            for (int i = 0; i < Number; i++)
                shiftedString += "0";
            return shiftedString;
        }

        private static string ShiftRowByByte(string Text, int ByteNumber, int ID)
        {
            int TotalSize;
            if (ID == 0)
                TotalSize = ByteNumber * 2;
            else
                TotalSize = Text.Length - ByteNumber * 2;
            string shiftedString = Text.Substring(TotalSize);
            for (int i = 0; i < TotalSize; i++)
            {
                shiftedString += Text[i];
            }
            return shiftedString;
        }
        static string XORTwoStringsBinary(string string1, string string2)
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


        static void ExpandInitialRound(string key)
        {
            StringBuilder word = new StringBuilder();
            int currWord = 0;
            for (int i = 0; i < 32; i++)
            {
                if (i > 0 && i % 8 == 0)
                {
                    Word[currWord++] = word.ToString();
                    word.Clear();
                }
                word.Append(key[i]);
            }
            Word[3] = word.ToString();

        }

        static string GetSBoxValue(string HexaString, int ID)
        {
            string Row = HexaString.Substring(0, HexaString.Length / 2);
            string Col = HexaString.Substring(HexaString.Length / 2, HexaString.Length / 2);

            if (Row.Length != 2)
                Row = Row + "0";
            if (Col.Length != 2)
                Col = "0" + Col;
            if (ID == 0)
                return ForwardHexaSBox[new KeyValuePair<string, string>(Row, Col)];
            return InverseHexaSBox[new KeyValuePair<string, string>(Row, Col)];

        }


        static string ApplyWordFunction(int EndOfPrevWord, int RoundConstantIndex)
        {
            string newWord = Word[EndOfPrevWord].Substring(2) + Word[EndOfPrevWord][0] + Word[EndOfPrevWord][1];
            string SBoxTotalOutput = "";
            for (int i = 0; i < newWord.Length; i += 2)
            {
                string B = newWord[i].ToString() + newWord[i + 1].ToString();
                SBoxTotalOutput += GetSBoxValue(B, 0);
            }
            string Z = BinaryStringToHexa(XORTwoStringsBinary(HexaToBinary(SBoxTotalOutput), HexaToBinary(RoundConstant[RoundConstantIndex] + "000000")));
            return BinaryStringToHexa(XORTwoStringsBinary(HexaToBinary(Z), HexaToBinary(Word[EndOfPrevWord - 3])));
        }
        static void MakeRoundKeys(string key)
        {
            key = key.ToUpper();
            ExpandInitialRound(key);
            int EndOfPrevWordIndex = 3;
            int RoundConstantIndex = 1;

            while (EndOfPrevWordIndex <= 40)
            {
                Word[EndOfPrevWordIndex + 1] = ApplyWordFunction(EndOfPrevWordIndex, RoundConstantIndex);
                for (int i = 2; i <= 4; i++)
                {
                    Word[EndOfPrevWordIndex + i] = BinaryStringToHexa(XORTwoStringsBinary(HexaToBinary(Word[EndOfPrevWordIndex + i - 1]), HexaToBinary(Word[EndOfPrevWordIndex + i - 4])));
                }

                EndOfPrevWordIndex += 4;
                RoundConstantIndex++;
            }
            int currKeyIndex = 0;
            StringBuilder curr = new StringBuilder("");
            for (int i = 0; i < 44; i++)
            {
                if (i != 0 && i % 4 == 0)
                {
                    RoundKey[currKeyIndex++] = curr.ToString();

                    curr.Clear();
                }
                curr.Append(Word[i]);
            }
            RoundKey[currKeyIndex] = curr.ToString();
        }

        static string AddRoundKey(string Text, string Key)
        {
            string BinaryOutput = XORTwoStringsBinary(HexaToBinary(Text), HexaToBinary(Key));
            return BinaryStringToHexa(BinaryOutput);
        }

        static string GetSubByteValue(string Text, int ID)
        {
            string TotalSBoxValues = "";
            for (int i = 0; i < Text.Length; i += 2)
            {
                string Cell = Text[i].ToString() + Text[i + 1].ToString();
                TotalSBoxValues += GetSBoxValue(Cell, ID);
            }
            return TotalSBoxValues;
        }

        static string GetShiftRowsValue(string Text, int ID)
        {
            string[] RowString = new string[4];
            int ctr = 0;
            for (int i = 0; i < Text.Length; i += 2)
            {
                string currBlock = Text[i].ToString() + Text[i + 1].ToString();
                RowString[ctr % 4] += currBlock;
                ctr++;
            }
            for (int i = 1; i <= 3; i++)
            {
                RowString[i] = ShiftRowByByte(RowString[i], i, ID);
            }
            string Ans = "";
            int currCol = 0;
            ctr = 0;
            for (int i = 0; i < Text.Length; i += 2)
            {
                if (ctr > 0 && ctr % 4 == 0)
                    currCol += 2;
                Ans += RowString[ctr % 4][currCol].ToString() + RowString[ctr % 4][currCol + 1].ToString();
                ctr++;
            }
            return Ans;
        }

        static string AESGaloisMultiply(string MixColsByte, string TextByte)
        {
            if (MixColsByte.Equals("01"))
                return TextByte;
            else if (MixColsByte.Equals("02"))
            {
                char TextByteFirstBit = HexaToBinary(TextByte)[0];
                string ShiftedTextByteValue = ShiftLefBitwiseOperator(HexaToBinary(TextByte), 1);
                if (TextByteFirstBit.Equals('1'))
                {
                    string FieldRepresentationConstant = "00011011";
                    return BinaryStringToHexa(
                        XORTwoStringsBinary(ShiftedTextByteValue, FieldRepresentationConstant)
                    );
                }
                return BinaryStringToHexa(ShiftedTextByteValue);
            }
            else
            {
                int num = BinaryStringToInt(HexaToBinary(MixColsByte));
                string ReturnedVal = "";
                if (num / 2 < 10)
                    ReturnedVal = AESGaloisMultiply("0" + (num / 2).ToString(), TextByte);
                else
                    ReturnedVal = AESGaloisMultiply((num / 2).ToString(), TextByte);
                if (num % 2 == 0)
                    return AESGaloisMultiply("02", ReturnedVal);
                else
                    return BinaryStringToHexa(
                     XORTwoStringsBinary(HexaToBinary(AESGaloisMultiply("02", ReturnedVal)), HexaToBinary(TextByte))
                    );
            }

        }

        static string GetAESGaloisMultiplicationHexa(string First, string Second)
        {
            string Curr = "";
            for (int i = 0; i < Second.Length; i += 2)
            {
                string MixColsByte = First[i].ToString() + First[i + 1].ToString();
                string TextByte = Second[i].ToString() + Second[i + 1].ToString();
                if (Curr.Length == 0)
                    Curr = AESGaloisMultiply(MixColsByte, TextByte);
                else
                    Curr = BinaryStringToHexa(
                        XORTwoStringsBinary(HexaToBinary(Curr), HexaToBinary(AESGaloisMultiply(MixColsByte, TextByte)))
                    );

            }

            return Curr;
        }

        static string GetMixColumnsValue(string Text, int ID)
        {
            string[] TextCols = new string[4];
            int ctr = 0;
            for (int i = 0; i < Text.Length; i += 2)
            {
                if (i > 0 && i % 8 == 0)
                    ctr++;
                TextCols[ctr] += Text[i].ToString() + Text[i + 1].ToString();
            }
            string Ans = "";
            for (int j = 0; j < 4; j++)
            {
                for (int k = 0; k < 4; k++)
                {
                    if (ID == 0)
                        Ans += GetAESGaloisMultiplicationHexa(MixColsTable[k], TextCols[j]);
                    else
                        Ans += GetAESGaloisMultiplicationHexa(MixColsTableInverse[k], TextCols[j]);

                }
            }
            return Ans;
        }


        public override string Decrypt(string cipherText, string key)
        {
            if (key.StartsWith("0x"))
                key = key.Substring(2);
            if (cipherText.StartsWith("0x"))
                cipherText = cipherText.Substring(2);
            key = key.ToUpper();
            cipherText = cipherText.ToUpper();
            MakeRoundKeys(key);
            string InitialPermutation = AddRoundKey(cipherText, RoundKey[10]);
            string CurrStart = InitialPermutation;
            for (int i = 9; i >= 1; i--)
            {
                string ShiftRowsOutput = GetShiftRowsValue(CurrStart, (int)Algorithm.DECRYPT);
                string SubByteOutput = GetSubByteValue(ShiftRowsOutput, (int)Algorithm.DECRYPT);
                string CurrentPermutation = AddRoundKey(SubByteOutput, RoundKey[i]);
                string MixColsOutput = GetMixColumnsValue(CurrentPermutation, (int)Algorithm.DECRYPT);
                if (MixColsOutput.Equals("991897a71e153b0873308408f1afdd0c".ToUpper()))
                    Console.WriteLine("RIGHT");
                CurrStart = MixColsOutput;
            }
            string FinalShiftRowsOutput = GetShiftRowsValue(CurrStart, (int)Algorithm.DECRYPT);
            string FinalSubByteOutput = GetSubByteValue(FinalShiftRowsOutput, (int)Algorithm.DECRYPT);
            string FinalPermutation = AddRoundKey(FinalSubByteOutput, RoundKey[0]);
            return "0x" + FinalPermutation;
        }

        public override string Encrypt(string plainText, string key)
        {
            if (key.StartsWith("0x"))
                key = key.Substring(2);
            if (plainText.StartsWith("0x"))
                plainText = plainText.Substring(2);
            key = key.ToUpper();
            plainText = plainText.ToUpper();
            MakeRoundKeys(key);
            Console.WriteLine();
            string InitialPermutation = AddRoundKey(plainText, RoundKey[0]);
            string CurrStart = InitialPermutation;
            Console.WriteLine(InitialPermutation);
            for (int i = 1; i <= 9; i++)
            {
                string SubByteOutput = GetSubByteValue(CurrStart, (int)Algorithm.ENCRYPT);
                Console.WriteLine(SubByteOutput);
                string ShiftRowsOutput = GetShiftRowsValue(SubByteOutput, (int)Algorithm.ENCRYPT);
                string MixColsOutput = GetMixColumnsValue(ShiftRowsOutput,(int)Algorithm.ENCRYPT);
                string CurrentPermutation = AddRoundKey(MixColsOutput, RoundKey[i]);
                CurrStart = CurrentPermutation;
            }
            string FinalSubByteOutput = GetSubByteValue(CurrStart, (int)Algorithm.ENCRYPT);
            string FinalShiftRowsOutput = GetShiftRowsValue(FinalSubByteOutput, (int)Algorithm.ENCRYPT);
            string FinalPermutation = AddRoundKey(FinalShiftRowsOutput, RoundKey[10]);
            return "0x" + FinalPermutation;
        }
    }
}
