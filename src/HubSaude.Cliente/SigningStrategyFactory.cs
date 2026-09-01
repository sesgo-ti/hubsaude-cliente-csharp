// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente;

/// <summary>
/// Parâmetros PSS equivalentes ao PSSParameterSpec do Java (RFC 7518 §3.5).
/// </summary>
/// <param name="DigestAlgorithm">Nome do digest (ex.: <c>SHA-384</c>).</param>
/// <param name="SaltLength">Comprimento do salt em bytes.</param>
public sealed record PssParameters(string DigestAlgorithm, int SaltLength);

/// <summary>
/// Factory de <see cref="ISigningStrategy"/> (RF-12, RF-16).
/// </summary>
public static class SigningStrategyFactory
{
    private const string ValidAlgorithms =
        "RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512";

    /// <summary>
    /// Cria estratégia a partir de chave RSA com algoritmo padrão (<c>SHA384withRSA</c>).
    /// </summary>
    /// <param name="privateKey">Chave privada RSA já carregada.</param>
    /// <returns>Estratégia que não assume ownership da chave.</returns>
    public static ISigningStrategy FromPrivateKey(RSA privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        return new PrivateKeySigningStrategy(privateKey);
    }

    /// <summary>
    /// Cria estratégia a partir de chave RSA com algoritmo JCA explícito.
    /// </summary>
    /// <param name="privateKey">Chave privada RSA já carregada.</param>
    /// <param name="algorithm">Nome JCA (ex.: <c>SHA384withRSA</c>, <c>RSASSA-PSS</c>).</param>
    /// <returns>Estratégia que não assume ownership da chave.</returns>
    public static ISigningStrategy FromPrivateKey(RSA privateKey, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(algorithm);
        return new PrivateKeySigningStrategy(privateKey, algorithm);
    }

    /// <summary>
    /// Cria estratégia a partir de chave ECDSA com algoritmo JCA explícito.
    /// </summary>
    /// <param name="privateKey">Chave privada ECDSA já carregada.</param>
    /// <param name="algorithm">Nome JCA (ex.: <c>SHA384withECDSAinP1363Format</c>).</param>
    /// <returns>Estratégia que não assume ownership da chave.</returns>
    public static ISigningStrategy FromPrivateKey(ECDsa privateKey, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(algorithm);
        return new PrivateKeySigningStrategy(privateKey, algorithm);
    }

    /// <summary>
    /// Carrega chave privada PEM de arquivo sem senha.
    /// </summary>
    /// <param name="keyPath">Caminho do arquivo PEM.</param>
    /// <returns>Estratégia com ownership da chave carregada.</returns>
    public static ISigningStrategy FromPemFile(string keyPath)
    {
        return FromPemFile(keyPath, password: null);
    }

    /// <summary>
    /// Carrega chave privada PEM de arquivo, com senha opcional.
    /// </summary>
    /// <param name="keyPath">Caminho do arquivo PEM.</param>
    /// <param name="password">Senha do PEM criptografado; nulo quando em claro.</param>
    /// <returns>Estratégia com ownership da chave carregada.</returns>
    public static ISigningStrategy FromPemFile(string keyPath, char[]? password)
    {
        ArgumentNullException.ThrowIfNull(keyPath);
        var key = PemLoader.LoadPrivateKey(keyPath, password);
        return WrapOwned(key, PrivateKeySigningStrategy.DefaultAlgorithm, pssHash: null);
    }

    /// <summary>
    /// Carrega chave privada a partir de conteúdo PEM em memória.
    /// </summary>
    /// <param name="pemContent">Texto PEM da chave.</param>
    /// <param name="password">Senha do PEM criptografado; nulo quando em claro.</param>
    /// <returns>Estratégia com ownership da chave carregada.</returns>
    public static ISigningStrategy FromPemString(string pemContent, char[]? password)
    {
        ArgumentNullException.ThrowIfNull(pemContent);
        var key = PemLoader.LoadPrivateKeyFromString(pemContent, password, "<string>");
        return WrapOwned(key, PrivateKeySigningStrategy.DefaultAlgorithm, pssHash: null);
    }

    /// <summary>
    /// Cria estratégia a partir de certificado com chave privada (PKCS#12 ou PEM composto).
    /// </summary>
    /// <param name="certificate">Certificado contendo a chave privada.</param>
    /// <returns>Estratégia com ownership da chave extraída.</returns>
    /// <exception cref="SmartTokenException">Certificado sem chave privada exportável.</exception>
    public static ISigningStrategy FromCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
        {
            return new PrivateKeySigningStrategy(
                rsa, PrivateKeySigningStrategy.DefaultAlgorithm, ownsKey: true, pssHash: null);
        }

        var ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa is not null)
        {
            return new PrivateKeySigningStrategy(
                ecdsa, PrivateKeySigningStrategy.DefaultAlgorithm, ownsKey: true);
        }

        throw new SmartTokenException("Chave n\u00e3o encontrada no KeyStore: (certificado sem chave privada)");
    }

    /// <summary>
    /// Carrega PKCS#12 em memória e devolve a estratégia de assinatura (RF-12).
    /// </summary>
    /// <param name="pkcs12">Bytes do arquivo PFX/P12.</param>
    /// <param name="alias">Alias ou nome simples da entrada com chave privada.</param>
    /// <param name="password">Senha do PKCS#12; nulo quando não protegido.</param>
    /// <returns>Estratégia com ownership da chave do certificado.</returns>
    public static ISigningStrategy FromPkcs12(byte[] pkcs12, string alias, char[]? password)
    {
        return FromCertificate(LoadPkcs12Certificate(pkcs12, alias, password));
    }

    /// <summary>
    /// Carrega PKCS#12 de arquivo e devolve a estratégia de assinatura (RF-12).
    /// </summary>
    public static ISigningStrategy FromPkcs12File(string path, string alias, char[]? password)
    {
        ArgumentNullException.ThrowIfNull(path);
        var bytes = File.ReadAllBytes(path);
        try
        {
            return FromPkcs12(bytes, alias, password);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    internal static X509Certificate2 LoadPkcs12Certificate(byte[] pkcs12, string alias, char[]? password)
    {
        ArgumentNullException.ThrowIfNull(pkcs12);
        ArgumentNullException.ThrowIfNull(alias);

        var passwordCopy = password is null ? null : (char[])password.Clone();
        try
        {
            var passwordText = passwordCopy is null ? null : new string(passwordCopy);
            var collection = X509CertificateLoader.LoadPkcs12Collection(
                pkcs12,
                passwordText,
                X509KeyStorageFlags.EphemeralKeySet);

            X509Certificate2? match = null;
            foreach (var cert in collection)
            {
                if (cert.HasPrivateKey && MatchesAlias(cert, alias))
                {
                    match = cert;
                    break;
                }
            }

            if (match is null)
            {
                throw new SmartTokenException("Chave n\u00e3o encontrada no KeyStore: " + alias);
            }

            return match;
        }
        catch (SmartTokenException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SmartTokenException("Falha ao obter chave do KeyStore: " + ex.Message, ex);
        }
        finally
        {
            PemLoader.ClearPassword(passwordCopy);
        }
    }

    /// <summary>
    /// Converte algoritmo JWT <c>alg</c> para nome JCA usado na assinatura (RF-16).
    /// </summary>
    /// <param name="jwtAlgorithm">Algoritmo JWT (ex.: <c>RS384</c>, <c>ES384</c>).</param>
    /// <returns>Nome JCA equivalente.</returns>
    /// <exception cref="SmartTokenException">Algoritmo não suportado.</exception>
    public static string JwtAlgorithmToJava(string jwtAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(jwtAlgorithm);
        return jwtAlgorithm.ToUpperInvariant() switch
        {
            "RS256" => "SHA256withRSA",
            "RS384" => "SHA384withRSA",
            "RS512" => "SHA512withRSA",
            "PS256" or "PS384" or "PS512" => "RSASSA-PSS",
            "ES256" => "SHA256withECDSAinP1363Format",
            "ES384" => "SHA384withECDSAinP1363Format",
            "ES512" => "SHA512withECDSAinP1363Format",
            _ => throw new SmartTokenException(
                "Algoritmo JWT n\u00e3o suportado: " + jwtAlgorithm
                + ". Algoritmos v\u00e1lidos: " + ValidAlgorithms),
        };
    }

    /// <summary>
    /// Devolve parâmetros PSS para algoritmos <c>PS*</c>; nulo para demais algoritmos.
    /// </summary>
    /// <param name="jwtAlgorithm">Algoritmo JWT (ex.: <c>PS384</c>).</param>
    /// <returns>Parâmetros PSS ou <c>null</c> quando não aplicável.</returns>
    public static PssParameters? PssParameterSpecFor(string jwtAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(jwtAlgorithm);
        return jwtAlgorithm.ToUpperInvariant() switch
        {
            "PS256" => new PssParameters("SHA-256", 32),
            "PS384" => new PssParameters("SHA-384", 48),
            "PS512" => new PssParameters("SHA-512", 64),
            _ => null,
        };
    }

    /// <summary>
    /// Cria estratégia a partir de chave já carregada, mapeando algoritmo JWT para JCA (RF-16).
    /// </summary>
    /// <param name="privateKey">Chave RSA ou ECDSA.</param>
    /// <param name="jwtAlgorithm">Algoritmo JWT desejado no header do assertion.</param>
    /// <returns>Estratégia que não assume ownership da chave.</returns>
    /// <exception cref="SmartTokenException">Tipo de chave ou algoritmo não suportado.</exception>
    public static ISigningStrategy FromPrivateKeyForJwt(AsymmetricAlgorithm privateKey, string jwtAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        var jca = JwtAlgorithmToJava(jwtAlgorithm);
        var pss = PssParameterSpecFor(jwtAlgorithm);
        var pssHash = pss is null ? (HashAlgorithmName?)null : HashFromDigest(pss.DigestAlgorithm);

        return privateKey switch
        {
            RSA rsa => new PrivateKeySigningStrategy(rsa, jca, ownsKey: false, pssHash),
            ECDsa ecdsa => new PrivateKeySigningStrategy(ecdsa, jca, ownsKey: false),
            _ => throw new SmartTokenException(
                "Tipo de chave n\u00e3o suportado para valida\u00e7\u00e3o: " + privateKey.GetType().Name),
        };
    }

    internal static HashAlgorithmName HashFromDigest(string digestAlgorithm)
    {
        return digestAlgorithm switch
        {
            "SHA-256" => HashAlgorithmName.SHA256,
            "SHA-384" => HashAlgorithmName.SHA384,
            "SHA-512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };
    }

    private static ISigningStrategy WrapOwned(AsymmetricAlgorithm key, string algorithm, HashAlgorithmName? pssHash)
    {
        return key switch
        {
            RSA rsa => new PrivateKeySigningStrategy(rsa, algorithm, ownsKey: true, pssHash),
            ECDsa ecdsa => new PrivateKeySigningStrategy(ecdsa, algorithm, ownsKey: true),
            _ => throw new SmartTokenException("Tipo de chave n\u00e3o suportado: " + key.GetType().Name),
        };
    }

    private static bool MatchesAlias(X509Certificate2 cert, string alias)
    {
        if (string.Equals(cert.FriendlyName, alias, StringComparison.Ordinal))
        {
            return true;
        }

        var simple = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        return string.Equals(simple, alias, StringComparison.Ordinal);
    }
}
