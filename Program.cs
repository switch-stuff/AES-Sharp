using System;
using System.IO;
using System.Linq;

namespace AES_Sharp
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] h(string Hex)
            {
                return Enumerable.Range(0, Hex.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(Hex.Substring(x, 2), 16)).ToArray();
            }

            File.WriteAllBytes(args[2] + ".out", Aes.CTR(h(args[0]), h(args[1]), File.ReadAllBytes(args[2])));
        }
    }
}