using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.IO;

namespace BcPgpCypherDemo
{
    public class Encrypter
    {
        private readonly string _publicKeyPath;

        public readonly CompressionAlgorithmTag _compressionAlgorithm;

        public Encrypter(string publicKeyPath, CompressionAlgorithmTag compressionAlgorithm = CompressionAlgorithmTag.Zip)
        {
            _publicKeyPath = publicKeyPath;

            _compressionAlgorithm = compressionAlgorithm;
        }

        public bool EncryptFile(string inputFileName, string outputFileName)
        {
            PgpPublicKey encKey;

            try
            {
                encKey = ReadPublicKey();
            }
            catch (PgpException) // it might be a secret key
            {
                encKey = FindPublicKey();
            }

            using (Stream output = File.Create(outputFileName))
            {
                return EncryptFile(inputFileName, output, encKey);
            }
        }

        private bool EncryptFile(string fileName, Stream outputStream, PgpPublicKey encKey)
        {
            MemoryStream ms = null;
            PgpCompressedDataGenerator compressedDataGenerator = null;
            PgpEncryptedDataGenerator encryptedDataGenerator = null;
            
            bool cdgClosed = false, edgClosed = false;

            try
            {
                ms = new MemoryStream();

                compressedDataGenerator = new PgpCompressedDataGenerator(_compressionAlgorithm);

                using (Stream compressedDataStream = compressedDataGenerator.Open(ms))
                {
                    PgpUtilities.WriteFileToLiteralData(compressedDataStream, PgpLiteralData.Binary, new FileInfo(fileName));

                    compressedDataGenerator.Close();
                    cdgClosed = true;
                }

                encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, true, new SecureRandom());
                encryptedDataGenerator.AddMethod(encKey);

                using (Stream encryptedDataStream = encryptedDataGenerator.Open(outputStream, ms.Length))
                {
                    ms.Seek(0, SeekOrigin.Begin);

                    byte[] buffer = new byte[65536];
                    int read = 0;

                    while ((read = ms.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        encryptedDataStream.Write(buffer, 0, read);
                    }
                }

                encryptedDataGenerator.Close();
                edgClosed = true;

                return true;
            }
            finally
            {
                if (ms != null) ms.Dispose();

                if (!cdgClosed) compressedDataGenerator?.Close();

                if (!edgClosed) encryptedDataGenerator?.Close();
            }
        }

        private PgpPublicKey ReadPublicKey()
        {
            PgpPublicKeyRingBundle pgpPub;

            using (Stream keyStream = File.OpenRead(_publicKeyPath))
            {
                pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyStream));
            }

            PgpPublicKey masterKey = null;
            PgpPublicKey subKey = null;

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (masterKey == null && key.IsMasterKey && key.IsEncryptionKey)
                    {
                        masterKey = key;
                    }
                    else if (subKey == null && !key.IsMasterKey && key.IsEncryptionKey)
                    {
                        subKey = key;
                    }
                }
            }

            PgpPublicKey foundKey = subKey ?? masterKey;

            if (foundKey == null)
            {
                throw new ArgumentException("Can't find encryption key in key ring.");
            }

            return foundKey;
        }

        private PgpPublicKey FindPublicKey()
        {
            PgpSecretKeyRingBundle pgpPub;

            using (Stream keyStream = File.OpenRead(_publicKeyPath))
            {
                pgpPub = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyStream));
            }

            PgpPublicKey masterKey = null;
            PgpPublicKey subKey = null;

            foreach (PgpSecretKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                {
                    if (masterKey == null && key.PublicKey.IsMasterKey && key.PublicKey.IsEncryptionKey)
                    {
                        masterKey = key.PublicKey;
                    }
                    else if (subKey == null && !key.PublicKey.IsMasterKey && key.PublicKey.IsEncryptionKey)
                    {
                        subKey = key.PublicKey;
                    }
                }
            }

            PgpPublicKey foundKey = subKey ?? masterKey;

            if (foundKey == null)
            {
                throw new ArgumentException("Can't find encryption key in key ring.");
            }

            return foundKey;
        }
    }
}
