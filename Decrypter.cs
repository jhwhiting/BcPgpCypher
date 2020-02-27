using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;

namespace BcPgpCypherDemo
{
    public class Decrypter
    {
        private readonly string _privateKeyPath;

        public readonly string _password;

        public Decrypter(string privateKeyPath, string password)
        {
            _privateKeyPath = privateKeyPath;

            _password = password;
        }

        public void DecryptFile(string inputFileName, string outputFileName)
        {
            using (Stream inputStream = File.OpenRead(inputFileName))
            using (Stream outputStream = File.Create(outputFileName))
            using (Stream keyInStream = File.OpenRead(_privateKeyPath))
            using (Stream decoderStream = PgpUtilities.GetDecoderStream(inputStream))
            {
                DecryptFile(decoderStream, outputStream, keyInStream);
            }
        }

        private void DecryptFile(Stream decoderStream, Stream outputStream, Stream keyIn)
        {
            PgpEncryptedDataList encryptedList = GetEncryptedList(decoderStream);

            // find the secret key

            PgpPrivateKey sKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));

            foreach (PgpPublicKeyEncryptedData pked in encryptedList.GetEncryptedDataObjects())
            {
                sKey = FindSecretKey(pgpSec, pked.KeyId, _password);

                if (sKey != null)
                {
                    pbe = pked;
                    break;
                }
            }

            if (sKey == null) throw new ArgumentException("Secret key for message not found!");

            PgpObject message = GetMessage(pbe, sKey);

            if (message is PgpCompressedData)
            {
                message = UncompressMessage((PgpCompressedData)message);
            }

            PipeMessageOut(message, outputStream);
        }

        private PgpEncryptedDataList GetEncryptedList(Stream decoderStream)
        {
            PgpObjectFactory pgpF = new PgpObjectFactory(decoderStream);

            PgpObject first = pgpF.NextPgpObject();

            // the first object might be a PGP marker packet.

            if (first is PgpEncryptedDataList)
            {
                return (PgpEncryptedDataList)first;
            }
            else
            {
                PgpObject second = pgpF.NextPgpObject();

                return (PgpEncryptedDataList)second;
            }
        }

        private PgpObject GetMessage(PgpPublicKeyEncryptedData encryptedData, PgpPrivateKey privateKey)
        {
            using (Stream clear = encryptedData.GetDataStream(privateKey))
            {
                PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                return plainFact.NextPgpObject();
            }
        }

        private PgpObject UncompressMessage(PgpCompressedData message)
        {
            using (Stream cDataStream = message.GetDataStream())
            {
                PgpObjectFactory pgpFact = new PgpObjectFactory(cDataStream);

                return pgpFact.NextPgpObject();
            }
        }

        private void PipeMessageOut(PgpObject message, Stream outputStream)
        {
            if (message is PgpLiteralData)
            {
                PgpLiteralData ld = (PgpLiteralData)message;

                using (Stream unc = ld.GetInputStream())
                {
                    Streams.PipeAll(unc, outputStream);
                }
            }
            else if (message is PgpOnePassSignatureList)
            {
                throw new PgpException("Encrypted message contains a signed message: not literal data!");
            }
            else
            {
                throw new PgpException("Message is not a simple encrypted file: Type unknown.");
            }
        }

        private PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyID, string password)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyID);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(password.ToCharArray());
        }
    }
}
