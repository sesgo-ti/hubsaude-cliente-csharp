// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace HubSaude.Cliente;

/// <summary>
/// Carregamento de chaves e certificados PEM (RF-12/RF-13).
/// </summary>
public static class PemLoader
{
    /// <summary>Tamanho mínimo do módulo RSA, em bits (NIST SP 800-57).</summary>
    public const int MinRsaKeyBits = 2048;

    /// <summary>Tamanho mínimo do campo EC, em bits (curva P-256).</summary>
    public const int MinEcFieldBits = 256;

    /// <summary>
    /// Rejeita chaves abaixo do mínimo normativo (fail-fast, RF-12).
    /// </summary>
    /// <param name="key">Chave RSA ou ECDsa a validar.</param>
    /// <param name="source">Identificador da origem (caminho ou rótulo) para mensagens de erro.</param>
    /// <exception cref="ArgumentException">Chave abaixo do mínimo aceito.</exception>
    public static void ValidateMinimumKeySize(AsymmetricAlgorithm key, string source)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(source);

        switch (key)
        {
            case RSA rsa:
                var rsaBits = rsa.KeySize;
                if (rsaBits < MinRsaKeyBits)
                {
                    throw new ArgumentException(
                        "Chave RSA de " + rsaBits + " bits rejeitada: o tamanho m\u00ednimo aceito \u00e9 "
                        + MinRsaKeyBits + " bits (NIST SP 800-57). Fonte: " + source,
                        nameof(key));
                }

                break;
            case ECDsa ecdsa:
                var ecBits = ecdsa.KeySize;
                if (ecBits < MinEcFieldBits)
                {
                    throw new ArgumentException(
                        "Chave EC com campo de " + ecBits + " bits rejeitada: a curva m\u00ednima aceita \u00e9 P-256 ("
                        + MinEcFieldBits + " bits, NIST SP 800-57). Fonte: " + source,
                        nameof(key));
                }

                break;
        }
    }

    /// <summary>
    /// Carrega chave privada PEM de arquivo sem senha.
    /// </summary>
    /// <param name="path">Caminho do arquivo PEM.</param>
    /// <returns>Instância <see cref="RSA"/> ou <see cref="ECDsa"/> com a chave.</returns>
    /// <exception cref="SmartTokenException">PEM inválido ou formato não suportado.</exception>
    public static AsymmetricAlgorithm LoadPrivateKey(string path)
    {
        return LoadPrivateKey(path, password: null);
    }

    /// <summary>
    /// Carrega chave privada PEM de arquivo, com senha opcional.
    /// </summary>
    /// <param name="path">Caminho do arquivo PEM.</param>
    /// <param name="password">Senha do PEM criptografado; nulo quando em claro.</param>
    /// <returns>Instância <see cref="RSA"/> ou <see cref="ECDsa"/> com a chave.</returns>
    /// <exception cref="SmartTokenException">PEM inválido, senha incorreta ou formato não suportado.</exception>
    public static AsymmetricAlgorithm LoadPrivateKey(string path, char[]? password)
    {
        ArgumentNullException.ThrowIfNull(path);
        var raw = File.ReadAllBytes(path);
        try
        {
            var chars = Encoding.UTF8.GetChars(raw);
            return LoadPrivateKeyFromChars(chars, password, path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    /// <summary>
    /// Carrega chave privada a partir de texto PEM em memória.
    /// </summary>
    /// <param name="pem">Conteúdo PEM da chave.</param>
    /// <param name="password">Senha do PEM criptografado; nulo quando em claro.</param>
    /// <param name="source">Identificador da origem para mensagens de erro.</param>
    /// <returns>Instância <see cref="RSA"/> ou <see cref="ECDsa"/> com a chave.</returns>
    /// <exception cref="SmartTokenException">PEM inválido, senha incorreta ou formato não suportado.</exception>
    public static AsymmetricAlgorithm LoadPrivateKeyFromString(string pem, char[]? password, string source)
    {
        ArgumentNullException.ThrowIfNull(pem);
        return LoadPrivateKeyFromChars(pem.ToCharArray(), password, source);
    }

    /// <summary>
    /// Carrega chave privada a partir de caracteres PEM; o buffer é zerado ao retornar.
    /// </summary>
    /// <param name="pem">Caracteres PEM da chave.</param>
    /// <param name="password">Senha do PEM criptografado; nulo quando em claro.</param>
    /// <param name="source">Identificador da origem para mensagens de erro.</param>
    /// <returns>Instância <see cref="RSA"/> ou <see cref="ECDsa"/> com a chave.</returns>
    /// <exception cref="SmartTokenException">PEM inválido, senha incorreta ou formato não suportado.</exception>
    public static AsymmetricAlgorithm LoadPrivateKeyFromChars(char[] pem, char[]? password, string source)
    {
        ArgumentNullException.ThrowIfNull(pem);
        ArgumentNullException.ThrowIfNull(source);

        try
        {
            if (pem.Length == 0 || !ContainsBeginMarker(pem))
            {
                throw new SmartTokenException("Arquivo PEM vazio ou inv\u00e1lido: " + source);
            }

            var span = pem.AsSpan();
            AsymmetricAlgorithm key;
            if (Contains(span, "-----BEGIN ENCRYPTED PRIVATE KEY-----"))
            {
                key = DecryptPkcs8(span, password, source);
            }
            else if (IsOpenSslTraditionalEncrypted(span))
            {
                key = DecryptOpenSsl(span, password, source);
            }
            else
            {
                key = ImportUnencrypted(span, source);
            }

            ValidateMinimumKeySize(key, source);
            return key;
        }
        finally
        {
            Array.Clear(pem);
            ClearPassword(password);
        }
    }

    /// <summary>
    /// Carrega e valida certificado X.509 PEM de arquivo (RF-14).
    /// </summary>
    /// <param name="path">Caminho do arquivo PEM do certificado.</param>
    /// <returns>Certificado validado quanto ao período de validade.</returns>
    /// <exception cref="SmartTokenException">PEM inválido ou certificado fora da validade.</exception>
    public static X509Certificate2 LoadCertificate(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        return CertificateValidator.ValidateFromPemFile(path);
    }

    /// <summary>
    /// Carrega e valida certificado X.509 a partir de conteúdo PEM em memória (RF-14).
    /// </summary>
    /// <param name="pem">Texto PEM do certificado.</param>
    /// <param name="source">Identificador da origem para mensagens de erro.</param>
    /// <returns>Certificado validado quanto ao período de validade.</returns>
    /// <exception cref="SmartTokenException">PEM inválido ou certificado fora da validade.</exception>
    public static X509Certificate2 LoadCertificateFromString(string pem, string source)
    {
        return CertificateValidator.ValidateFromPem(pem, source);
    }

    internal static void ClearPassword(char[]? password)
    {
        if (password is not null && password.Length > 0)
        {
            Array.Clear(password);
        }
    }

    private static bool ContainsBeginMarker(char[] pem)
    {
        return Contains(pem, "-----BEGIN ");
    }

    private static bool IsOpenSslTraditionalEncrypted(ReadOnlySpan<char> pem)
    {
        return Contains(pem, "DEK-Info:") || Contains(pem, "Proc-Type: 4,ENCRYPTED");
    }

    private static bool Contains(ReadOnlySpan<char> haystack, string needle)
    {
        return haystack.IndexOf(needle.AsSpan(), StringComparison.Ordinal) >= 0;
    }

    private static AsymmetricAlgorithm ImportUnencrypted(ReadOnlySpan<char> pem, string source)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            rsa.Dispose();
            if (ex is ArgumentException && Contains(pem, "-----BEGIN CERTIFICATE-----"))
            {
                throw new SmartTokenException("Formato de chave n\u00e3o suportado (PemObject): " + source, ex);
            }
        }

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(pem);
            return ecdsa;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            ecdsa.Dispose();
            throw new SmartTokenException("Formato de chave n\u00e3o suportado (PemObject): " + source, ex);
        }
    }

    private static AsymmetricAlgorithm DecryptPkcs8(ReadOnlySpan<char> pem, char[]? password, string source)
    {
        if (password is null || password.Length == 0)
        {
            throw new SmartTokenException("Chave PKCS#8 criptografada requer senha: " + source);
        }

        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromEncryptedPem(pem, password);
            return rsa;
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
        }

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromEncryptedPem(pem, password);
            return ecdsa;
        }
        catch (CryptographicException ex)
        {
            ecdsa.Dispose();
            throw new SmartTokenException(
                "Falha ao decriptar chave PKCS#8 (senha incorreta?): " + source, ex);
        }
    }

    private static AsymmetricAlgorithm DecryptOpenSsl(ReadOnlySpan<char> pem, char[]? password, string source)
    {
        if (password is null || password.Length == 0)
        {
            throw new SmartTokenException("Chave criptografada (OpenSSL) requer senha: " + source);
        }

        try
        {
            using var reader = new StringReader(pem.ToString());
            var pemReader = new PemReader(reader, new PasswordFinder(password));
            var obj = pemReader.ReadObject()
                ?? throw new SmartTokenException("Arquivo PEM vazio ou inv\u00e1lido: " + source);

            var privateKey = obj switch
            {
                AsymmetricCipherKeyPair pair => pair.Private,
                AsymmetricKeyParameter param => param,
                _ => throw new SmartTokenException(
                    "Formato de chave n\u00e3o suportado (" + obj.GetType().Name + "): " + source),
            };

            return ConvertBcKey(privateKey, source);
        }
        catch (SmartTokenException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SmartTokenException(
                "Falha ao decriptar chave OpenSSL (senha incorreta?): " + source, ex);
        }
    }

    private static AsymmetricAlgorithm ConvertBcKey(AsymmetricKeyParameter privateKey, string source)
    {
        if (privateKey is RsaPrivateCrtKeyParameters rsaParams)
        {
            var rsa = RSA.Create();
            rsa.ImportParameters(DotNetUtilities.ToRSAParameters(rsaParams));
            return rsa;
        }

        if (privateKey is ECPrivateKeyParameters)
        {
            var pkcs8 = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).GetEncoded();
            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(pkcs8, out _);
            return ecdsa;
        }

        throw new SmartTokenException(
            "Formato de chave n\u00e3o suportado (" + privateKey.GetType().Name + "): " + source);
    }

    private sealed class PasswordFinder : IPasswordFinder
    {
        private readonly char[] _password;

        internal PasswordFinder(char[] password)
        {
            _password = password;
        }

        public char[] GetPassword()
        {
            return (char[])_password.Clone();
        }
    }
}
