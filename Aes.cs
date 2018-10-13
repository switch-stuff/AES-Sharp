namespace AES_Sharp
{
    public class Aes
    {
        private static uint[][] ExpandedKey;
        private static uint C0, C1, C2, C3;

        private static uint BU(byte[] B, int Ofs)
        {
            return B[Ofs] |
                (uint)B[Ofs + 1] << 8 |
                (uint)B[Ofs + 2] << 16 |
                (uint)B[Ofs + 3] << 24;
        }

        private static void BE(uint N, byte[] B, int Ofs)
        {
            B[Ofs] = (byte)(N);
            B[Ofs + 1] = (byte)(N >> 8);
            B[Ofs + 2] = (byte)(N >> 16);
            B[Ofs + 3] = (byte)(N >> 24);
        }

        private static readonly byte[] SubBox =
    {
                0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            };

        private static readonly byte[] SubBoxInv =
            {
                0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
            };

        private static readonly byte[] RoundConst =
            {
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F,
                0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91
            };

        private static uint Shift(uint Val, int Num)
        {
            return (Val >> Num) | (Val << (32 - Num));
        }

        private static uint MixColumns(uint X)
        {
            uint T0 = Shift(X, 8);
            uint T1 = X ^ T0;
            return Shift(T1, 16) ^ T0 ^ Mult(T1);
        }

        private static uint UnmixColumns(uint X)
        {
            var T0 = X;
            var T1 = T0 ^ Shift(T0, 8);
            T0 ^= Mult(T1);
            T1 ^= Mult2(T0);
            T0 ^= T1 ^ Shift(T1, 16);
            return T0;
        }

        private static uint SubTransform(uint X)
        {
            return
                SubBox[X & 0xFF] |
                (uint)SubBox[(X >> 8) & 0xFF] << 8 |
                (uint)SubBox[(X >> 16) & 0xFF] << 16 |
                (uint)SubBox[(X >> 24) & 0xFF] << 24;
        }

        private static uint Mult(uint X)
        {
            return ((X & 0x7f7f7f7f) << 1) ^ (((X & 0x80808080) >> 7) * 27);
        }

        private static uint Mult2(uint X)
        {
            var T = X & 0xc0c0c0c0;
            T ^= (T >> 1);
            return ((X & 0x3f3f3f3f) << 2) ^ (T >> 2) ^ (T >> 5);
        }

        private static uint[][] GenWorkingKey(byte[] Key, bool Enc)
        {
            var KeyData = new uint[11][];

            for (int i = 0; i <= 10; ++i)
            {
                KeyData[i] = new uint[4];
            }

            var T0 = BU(Key, 0); KeyData[0][0] = T0;
            var T1 = BU(Key, 4); KeyData[0][1] = T1;
            var T2 = BU(Key, 8); KeyData[0][2] = T2;
            var T3 = BU(Key, 12); KeyData[0][3] = T3;

            for (int i = 1; i <= 10; ++i)
            {
                var U = SubTransform(Shift(T3, 8)) ^ RoundConst[i - 1];
                T0 ^= U; KeyData[i][0] = T0;
                T1 ^= T0; KeyData[i][1] = T1;
                T2 ^= T1; KeyData[i][2] = T2;
                T3 ^= T2; KeyData[i][3] = T3;
            }

            if (!Enc)
            {
                for (int i = 1; i < 10; i++)
                {
                    uint[] N = KeyData[i];
                    for (int n = 0; n < 4; n++)
                    {
                        N[n] = UnmixColumns(N[n]);
                    }
                }
            }

            return KeyData;
        }

        private static void EncryptBlock(uint[][] KB)
        {
            uint[] K = KB[0];
            uint T0 = C0 ^ K[0], T1 = C1 ^ K[1], T2 = C2 ^ K[2], R0, R1, R2, R3 = C3 ^ K[3], R = 1;

            while (R < 9)
            {
                K = KB[R++];

                R0 = MixColumns(SubBox[T0 & 0xFF] ^ (((uint)SubBox[(T1 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(T2 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(R3 >> 24) & 0xFF]) << 24)) ^ K[0];
                R1 = MixColumns(SubBox[T1 & 0xFF] ^ (((uint)SubBox[(T2 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(R3 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(T0 >> 24) & 0xFF]) << 24)) ^ K[1];
                R2 = MixColumns(SubBox[T2 & 0xFF] ^ (((uint)SubBox[(R3 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(T0 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(T1 >> 24) & 0xFF]) << 24)) ^ K[2];
                R3 = MixColumns(SubBox[R3 & 0xFF] ^ (((uint)SubBox[(T0 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(T1 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(T2 >> 24) & 0xFF]) << 24)) ^ K[3];

                K = KB[R++];

                T0 = MixColumns(SubBox[R0 & 0xFF] ^ (((uint)SubBox[(R1 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(R2 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(R3 >> 24) & 0xFF]) << 24)) ^ K[0];
                T1 = MixColumns(SubBox[R1 & 0xFF] ^ (((uint)SubBox[(R2 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(R3 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(R0 >> 24) & 0xFF]) << 24)) ^ K[1];
                T2 = MixColumns(SubBox[R2 & 0xFF] ^ (((uint)SubBox[(R3 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(R0 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(R1 >> 24) & 0xFF]) << 24)) ^ K[2];
                R3 = MixColumns(SubBox[R3 & 0xFF] ^ (((uint)SubBox[(R0 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(R1 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(R2 >> 24) & 0xFF]) << 24)) ^ K[3];
            }

            K = KB[R++];

            R0 = MixColumns(SubBox[T0 & 0xFF] ^ (((uint)SubBox[(T1 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(T2 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(R3 >> 24) & 0xFF]) << 24)) ^ K[0];
            R1 = MixColumns(SubBox[T1 & 0xFF] ^ (((uint)SubBox[(T2 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(R3 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(T0 >> 24) & 0xFF]) << 24)) ^ K[1];
            R2 = MixColumns(SubBox[T2 & 0xFF] ^ (((uint)SubBox[(R3 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(T0 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(T1 >> 24) & 0xFF]) << 24)) ^ K[2];
            R3 = MixColumns(SubBox[R3 & 0xFF] ^ (((uint)SubBox[(T0 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(T1 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(T2 >> 24) & 0xFF]) << 24)) ^ K[3];

            K = KB[R];

            C0 = SubBox[R0 & 0xFF] ^ (((uint)SubBox[(R1 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(R2 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(R3 >> 24) & 0xFF]) << 24) ^ K[0];
            C1 = SubBox[R1 & 0xFF] ^ (((uint)SubBox[(R2 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(R3 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(R0 >> 24) & 0xFF]) << 24) ^ K[1];
            C2 = SubBox[R2 & 0xFF] ^ (((uint)SubBox[(R3 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(R0 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(R1 >> 24) & 0xFF]) << 24) ^ K[2];
            C3 = SubBox[R3 & 0xFF] ^ (((uint)SubBox[(R0 >> 8) & 0xFF]) << 8) ^ (((uint)SubBox[(R1 >> 16) & 0xFF]) << 16) ^ (((uint)SubBox[(R2 >> 24) & 0xFF]) << 24) ^ K[3];
        }

        private static void DecryptBlock(uint[][] KB)
        {
            uint[] K = KB[10];
            uint T0 = C0 ^ K[0], T1 = C1 ^ K[1], T2 = C2 ^ K[2], R0, R1, R2, R3 = C3 ^ K[3], R = 9;

            while (R > 1)
            {
                K = KB[R--];

                R0 = UnmixColumns(SubBoxInv[T0 & 0xFF] ^ (((uint)SubBoxInv[(R3 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(T2 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(T1 >> 24) & 0xFF] << 24)) ^ K[0];
                R1 = UnmixColumns(SubBoxInv[T1 & 0xFF] ^ (((uint)SubBoxInv[(T0 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(R3 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(T2 >> 24) & 0xFF] << 24)) ^ K[1];
                R2 = UnmixColumns(SubBoxInv[T2 & 0xFF] ^ (((uint)SubBoxInv[(T1 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(T0 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(R3 >> 24) & 0xFF] << 24)) ^ K[2];
                R3 = UnmixColumns(SubBoxInv[R3 & 0xFF] ^ (((uint)SubBoxInv[(T2 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(T1 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(T0 >> 24) & 0xFF] << 24)) ^ K[3];

                K = KB[R--];

                T0 = UnmixColumns(SubBoxInv[R0 & 0xFF] ^ (((uint)SubBoxInv[(R3 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(R2 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(R1 >> 24) & 0xFF] << 24)) ^ K[0];
                T1 = UnmixColumns(SubBoxInv[R1 & 0xFF] ^ (((uint)SubBoxInv[(R0 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(R3 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(R2 >> 24) & 0xFF] << 24)) ^ K[1];
                T2 = UnmixColumns(SubBoxInv[R2 & 0xFF] ^ (((uint)SubBoxInv[(R1 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(R0 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(R3 >> 24) & 0xFF] << 24)) ^ K[2];
                R3 = UnmixColumns(SubBoxInv[R3 & 0xFF] ^ (((uint)SubBoxInv[(R2 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(R1 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(R0 >> 24) & 0xFF] << 24)) ^ K[3];
            }

            K = KB[1];

            R0 = UnmixColumns(SubBoxInv[T0 & 0xFF] ^ (((uint)SubBoxInv[(R3 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(T2 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(T1 >> 24) & 0xFF] << 24)) ^ K[0];
            R1 = UnmixColumns(SubBoxInv[T1 & 0xFF] ^ (((uint)SubBoxInv[(T0 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(R3 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(T2 >> 24) & 0xFF] << 24)) ^ K[1];
            R2 = UnmixColumns(SubBoxInv[T2 & 0xFF] ^ (((uint)SubBoxInv[(T1 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(T0 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(R3 >> 24) & 0xFF] << 24)) ^ K[2];
            R3 = UnmixColumns(SubBoxInv[R3 & 0xFF] ^ (((uint)SubBoxInv[(T2 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(T1 >> 16) & 0xFF]) << 16) ^ ((uint)SubBoxInv[(T0 >> 24) & 0xFF] << 24)) ^ K[3];

            K = KB[0];

            C0 = SubBoxInv[R0 & 0xFF] ^ (((uint)SubBoxInv[(R3 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(R2 >> 16) & 0xFF]) << 16) ^ (((uint)SubBoxInv[(R1 >> 24) & 0xFF]) << 24) ^ K[0];
            C1 = SubBoxInv[R1 & 0xFF] ^ (((uint)SubBoxInv[(R0 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(R3 >> 16) & 0xFF]) << 16) ^ (((uint)SubBoxInv[(R2 >> 24) & 0xFF]) << 24) ^ K[1];
            C2 = SubBoxInv[R2 & 0xFF] ^ (((uint)SubBoxInv[(R1 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(R0 >> 16) & 0xFF]) << 16) ^ (((uint)SubBoxInv[(R3 >> 24) & 0xFF]) << 24) ^ K[2];
            C3 = SubBoxInv[R3 & 0xFF] ^ (((uint)SubBoxInv[(R2 >> 8) & 0xFF]) << 8) ^ (((uint)SubBoxInv[(R1 >> 16) & 0xFF]) << 16) ^ (((uint)SubBoxInv[(R0 >> 24) & 0xFF]) << 24) ^ K[3];
        }

        private static void ProcessBlock(byte[] Input, int InOffset, byte[] Output, int OutOffset, bool Enc)
        {
            C0 = BU(Input, InOffset);
            C1 = BU(Input, InOffset + 4);
            C2 = BU(Input, InOffset + 8);
            C3 = BU(Input, InOffset + 12);

            if (Enc) EncryptBlock(ExpandedKey);
            else DecryptBlock(ExpandedKey);

            BE(C0, Output, OutOffset);
            BE(C1, Output, OutOffset + 4);
            BE(C2, Output, OutOffset + 8);
            BE(C3, Output, OutOffset + 12);
        }

        public static byte[] ECB(byte[] Key, byte[] Input, bool Enc)
        {
            var Buf = new byte[Input.Length];

            ExpandedKey = GenWorkingKey(Key, Enc);

            for (int i = 0; i < Input.Length; i += Key.Length)
            {
                ProcessBlock(Input, i, Buf, i, Enc);
            }

            return Buf;
        }

        public static byte[] CTR(byte[] Key, byte[] IV, byte[] Input)
        {
            var Buf = new byte[Input.Length];
            var KeyBuf = new byte[16];

            ExpandedKey = GenWorkingKey(Key, true);

            void Increment(byte[] Val)
            {
                int Pos = 16;
                while (--Pos >= 0 && ++Val[Pos] == 0) { }
            }

            for (int i = 0; i < Input.Length; i += 16)
            {
                ProcessBlock(IV, 0, KeyBuf, 0, true);
                for (int j = 0; j < 16; j++)
                {
                    Buf[i + j] = (byte)(KeyBuf[j] ^ Input[i + j]);
                }
                Increment(IV);
            }

            return Buf;
        }
    }
}