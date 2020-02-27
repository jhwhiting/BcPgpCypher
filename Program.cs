using System;
using System.IO;

namespace BcPgpCypherDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            File.WriteAllText("input.txt", "hello world!");

            Encrypter encrypter = new Encrypter("public.pkr");

            encrypter.EncryptFile("input.txt", "encrypted.pgp");

            Decrypter decrypter = new Decrypter("private.skr", "BcPgpCypherDemo");

            decrypter.DecryptFile("encrypted.pgp", "decrypted.txt");

            Console.WriteLine(File.ReadAllText("decrypted.txt"));
            Console.ReadKey();
        }
    }
}
