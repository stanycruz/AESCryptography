using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleAESCryptography
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Console.Write("Digite o valor a ser Criptografado: ");
                string original = Console.ReadLine();

                // Cria uma nova instância da classe Aes.
                // Isso gera uma nova chave e vetor de inicialização (IV).
                using (var random = new RNGCryptoServiceProvider())
                {
                    //AesManaged aes = new AesManaged();
                    //aes.GenerateKey();
                    //aes.GenerateIV();

                    //var key = aes.Key;

                    var key = Encoding.ASCII.GetBytes("XqXF3yQb3bZWXL0=");

                    byte[] encrypted = EncryptStringToBytes_Aes(original, key);

                    string roundTrip = DecryptStringFromBytes_Aes(encrypted, key);

                    Console.WriteLine();

                    // Exibe os dados originais e os dados descriptografados.
                    Console.WriteLine($"Original:                   {original}");
                    Console.WriteLine($"Criptografado (b64-encode): {Convert.ToBase64String(encrypted)}");
                    Console.WriteLine($"Descriptografado:           {roundTrip}");
                    Console.ReadKey();
                }

            }
            catch (Exception e)
            {
                Console.WriteLine($"Erro: {e.Message}");
                Console.ReadKey();
            }
        }

        #region Criptografa

        /// <summary>
        /// Criptografa a string para um array de bytes.
        /// </summary>
        /// <param name="plainText">Texto original</param>
        /// <param name="key">Chave de criptografia</param>
        /// <returns>Retorna os bytes criptografados do fluxo de memória.</returns>
        private static byte[] EncryptStringToBytes_Aes(string plainText, byte[] key)
        {
            byte[] encrypted;
            byte[] IV;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;

                aesAlg.GenerateIV();
                IV = aesAlg.IV;

                aesAlg.Mode = CipherMode.CBC;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Cria os fluxos usados ​​para criptografia. 
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            // Escreve todos os dados no fluxo.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            var combinedIvCt = new byte[IV.Length + encrypted.Length];
            Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
            Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);

            return combinedIvCt;
        }

        #endregion

        #region Descriptografa

        /// <summary>
        /// Descriptografa os bytes para uma sequência de caracteres.
        /// </summary>
        /// <param name="encrypted">Bytes que foram criptografados</param>
        /// <param name="key">Chave de criptografia</param>
        /// <returns>Caracteres descriptografados</returns>
        private static string DecryptStringFromBytes_Aes(byte[] encrypted, byte[] key)
        {
            // Declara a sequência usada
            // para conter o texto descriptografado.
            string plaintext = null;

            // Cria um objeto Aes com a chave especificada
            // e o vetor de inicialização (IV).
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;

                byte[] IV = new byte[aesAlg.BlockSize / 8];
                byte[] cipherText = new byte[encrypted.Length - IV.Length];

                Array.Copy(encrypted, IV, IV.Length);
                Array.Copy(encrypted, IV.Length, cipherText, 0, cipherText.Length);

                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;

                // Cria um decodificador para executar a transformação de fluxo.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Cria os fluxos usados ​​para descriptografia.
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Lê os bytes descriptografados no fluxo
                            // e os coloca em uma sequência de caracteres.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        #endregion
    }
}
