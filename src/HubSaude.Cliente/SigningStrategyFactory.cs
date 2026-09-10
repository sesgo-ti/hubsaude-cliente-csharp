// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente;

/// <summary>
/// Parâmetros PSS usados em <c>PS256</c>/<c>PS384</c>/<c>PS512</c> (RFC 7518 §3.5).
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
    /// Cria estratégia a partir de chave RSA com algoritmo padrão (<c>RS384</c>).
    /// </summary>
    /// <param name="privateKey">Chave privada RSA já carregada.</param>
    /// <returns>Estratégia que não assume ownership da chave.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="privateKey"/> é nulo.</exception>
    /// <exception cref="ArgumentException">A chave está abaixo do tamanho mínimo aceito.</exception>
    public static ISigningStrategy FromPrivateKey(RSA privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        return new PrivateKeySigningStrategy(privateKey);
    }

    /// <summary>
    /// Cria estratégia a partir de chave RSA com algoritmo de assinatura explícito.
    /// </summary>
    /// <param name="privateKey">Chave privada RSA já carregada.</param>
    /// <param name="algorithm">
    /// Algoritmo JWT (<c>RS256</c>, <c>RS384</c>, <c>RS512</c>, <c>PS256</c>,
    /// <c>PS384</c>, <c>PS512</c>) ou identificador de assinatura legado ainda aceito.
    /// </param>
    /// <returns>Estratégia que não assume ownership da chave.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="privateKey"/> ou <paramref name="algorithm"/> é nulo.
    /// </exception>
    /// <exception cref="ArgumentException">A chave está abaixo do tamanho mínimo aceito.</exception>
    public static ISigningStrategy FromPrivateKey(RSA privateKey, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(algorithm);
        return new PrivateKeySigningStrategy(privateKey, algorithm);
    }

    /// <summary>
    /// Cria estratégia a partir de chave ECDSA com algoritmo de assinatura explícito.
    /// </summary>
    /// <param name="privateKey">Chave privada ECDSA já carregada.</param>
    /// <param name="algorithm">
    /// Algoritmo JWT (<c>ES256</c>, <c>ES384</c>, <c>ES512</c>) ou identificador
    /// de assinatura legado ainda aceito.
    /// </param>
    /// <returns>Estratégia que não assume ownership da chave.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="privateKey"/> ou <paramref name="algorithm"/> é nulo.
    /// </exception>
    /// <exception cref="ArgumentException">A chave está abaixo do tamanho mínimo aceito.</exception>
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
    /// <exception cref="ArgumentNullException"><paramref name="keyPath"/> é nulo.</exception>
    /// <exception cref="SmartTokenException">PEM inválido ou formato não suportado.</exception>
    /// <exception cref="IOException">Falha ao ler o arquivo.</exception>
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
    /// <exception cref="ArgumentNullException"><paramref name="keyPath"/> é nulo.</exception>
    /// <exception cref="SmartTokenException">PEM inválido, senha incorreta ou formato não suportado.</exception>
    /// <exception cref="IOException">Falha ao ler o arquivo.</exception>
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
    /// <exception cref="ArgumentNullException"><paramref name="pemContent"/> é nulo.</exception>
    /// <exception cref="SmartTokenException">PEM inválido, senha incorreta ou formato não suportado.</exception>
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
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> é nulo.</exception>
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

        throw new SmartTokenException("Certificado sem chave privada exportável.");
    }

    /// <summary>
    /// Carrega PKCS#12 em memória e devolve a estratégia de assinatura (RF-12).
    /// </summary>
    /// <param name="pkcs12">Bytes do arquivo PFX/P12.</param>
    /// <param name="alias">Alias ou nome simples da entrada com chave privada.</param>
    /// <param name="password">Senha do PKCS#12; nulo quando não protegido.</param>
    /// <returns>Estratégia com ownership da chave do certificado.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="pkcs12"/> ou <paramref name="alias"/> é nulo.
    /// </exception>
    /// <exception cref="SmartTokenException">
    /// PKCS#12 inválido, senha incorreta, alias inexistente ou certificado sem chave privada.
    /// </exception>
    public static ISigningStrategy FromPkcs12(byte[] pkcs12, string alias, char[]? password)
    {
        return FromCertificate(LoadPkcs12Certificate(pkcs12, alias, password));
    }

    /// <summary>
    /// Cria estratégia a partir da chave privada de um arquivo PKCS#12/PFX.
    /// </summary>
    /// <param name="path">Caminho do arquivo PFX/P12.</param>
    /// <param name="alias">Alias ou nome simples da entrada com chave privada.</param>
    /// <param name="password">Senha do PKCS#12; nulo quando não protegido.</param>
    /// <returns>Estratégia com ownership da chave do certificado.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="path"/> ou <paramref name="alias"/> é nulo.
    /// </exception>
    /// <exception cref="SmartTokenException">
    /// PKCS#12 inválido, senha incorreta, alias inexistente ou certificado sem chave privada.
    /// </exception>
    /// <exception cref="IOException">Falha ao ler o arquivo.</exception>
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

    /// <summary>
    /// Cria estratégia que assina no HSM/token via PKCS#11. A chave nunca sai do hardware.
    /// Combine com <see cref="SmartTokenClientBuilder.ClientCertificate"/> ou
    /// <see cref="SmartTokenClientBuilder.ClientPkcs12(byte[], string, char[])"/> para mTLS.
    /// </summary>
    /// <param name="options">Caminho do módulo, PIN, chave e algoritmo JWT.</param>
    /// <returns>Estratégia que mantém a sessão PKCS#11 aberta até <see cref="IDisposable.Dispose"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> é nulo.</exception>
    /// <exception cref="ArgumentException">Opções incompletas ou mutuamente exclusivas.</exception>
    /// <exception cref="SmartTokenException">Falha ao abrir o módulo, o token ou a chave PKCS#11.</exception>
    public static ISigningStrategy FromPkcs11(Pkcs11Options options)
    {
        return Pkcs11SigningStrategy.Open(options);
    }

    internal static X509Certificate2 LoadPkcs12Certificate(byte[] pkcs12, string alias, char[]? password)
    {
        ArgumentNullException.ThrowIfNull(pkcs12);
        ArgumentNullException.ThrowIfNull(alias);

        return Pkcs12KeyStorage.LoadCertificate(pkcs12, alias, password);
    }

    /// <summary>
    /// Normaliza o algoritmo JWT <c>alg</c> para o identificador canônico em maiúsculas (RF-16).
    /// </summary>
    /// <param name="jwtAlgorithm">Algoritmo JWT (ex.: <c>RS384</c>, <c>es256</c>).</param>
    /// <returns>Identificador JWT em maiúsculas (ex.: <c>RS384</c>).</returns>
    /// <exception cref="ArgumentNullException"><paramref name="jwtAlgorithm"/> é nulo.</exception>
    /// <exception cref="SmartTokenException">Algoritmo não suportado.</exception>
    public static string NormalizeJwtAlgorithm(string jwtAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(jwtAlgorithm);
        var normalized = jwtAlgorithm.ToUpperInvariant();
        return normalized switch
        {
            "RS256" or "RS384" or "RS512"
                or "PS256" or "PS384" or "PS512"
                or "ES256" or "ES384" or "ES512" => normalized,
            _ => throw new SmartTokenException(
                "Algoritmo JWT n\u00e3o suportado: " + jwtAlgorithm
                + ". Algoritmos v\u00e1lidos: " + ValidAlgorithms),
        };
    }

    /// <summary>
    /// Converte algoritmo JWT <c>alg</c> para um identificador de assinatura legado.
    /// </summary>
    /// <param name="jwtAlgorithm">Algoritmo JWT (ex.: <c>RS384</c>, <c>ES384</c>).</param>
    /// <returns>Identificador legado equivalente (compatibilidade).</returns>
    /// <exception cref="ArgumentNullException"><paramref name="jwtAlgorithm"/> é nulo.</exception>
    /// <exception cref="SmartTokenException">Algoritmo não suportado.</exception>
    [Obsolete("Use NormalizeJwtAlgorithm para o identificador JWT (RS384, ES256, …). Este método devolve nomes no estilo JCA apenas para compatibilidade.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static string JwtAlgorithmToJava(string jwtAlgorithm)
    {
        return MapJwtAlgorithmToLegacyIdentifier(NormalizeJwtAlgorithm(jwtAlgorithm));
    }

    /// <summary>
    /// Devolve parâmetros PSS para algoritmos <c>PS*</c>; nulo para demais algoritmos.
    /// </summary>
    /// <param name="jwtAlgorithm">Algoritmo JWT (ex.: <c>PS384</c>).</param>
    /// <returns>Parâmetros PSS ou <c>null</c> quando não aplicável.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="jwtAlgorithm"/> é nulo.</exception>
    public static PssParameters? PssParametersFor(string jwtAlgorithm)
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
    /// Devolve parâmetros PSS para algoritmos <c>PS*</c>; nulo para demais algoritmos.
    /// </summary>
    /// <param name="jwtAlgorithm">Algoritmo JWT (ex.: <c>PS384</c>).</param>
    /// <returns>Parâmetros PSS ou <c>null</c> quando não aplicável.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="jwtAlgorithm"/> é nulo.</exception>
    [Obsolete("Use PssParametersFor.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static PssParameters? PssParameterSpecFor(string jwtAlgorithm)
    {
        return PssParametersFor(jwtAlgorithm);
    }

    /// <summary>
    /// Cria estratégia a partir de chave já carregada, mapeando o algoritmo JWT (RF-16).
    /// </summary>
    /// <param name="privateKey">Chave RSA ou ECDSA.</param>
    /// <param name="jwtAlgorithm">Algoritmo JWT desejado no header do assertion.</param>
    /// <returns>Estratégia que não assume ownership da chave.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="privateKey"/> ou <paramref name="jwtAlgorithm"/> é nulo.
    /// </exception>
    /// <exception cref="ArgumentException">A chave está abaixo do tamanho mínimo aceito.</exception>
    /// <exception cref="SmartTokenException">Tipo de chave ou algoritmo não suportado.</exception>
    public static ISigningStrategy FromPrivateKeyForJwt(AsymmetricAlgorithm privateKey, string jwtAlgorithm)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        var jwt = NormalizeJwtAlgorithm(jwtAlgorithm);
        var pss = PssParametersFor(jwt);
        var pssHash = pss is null ? (HashAlgorithmName?)null : HashFromDigest(pss.DigestAlgorithm);

        return privateKey switch
        {
            RSA rsa => new PrivateKeySigningStrategy(rsa, jwt, ownsKey: false, pssHash),
            ECDsa ecdsa => new PrivateKeySigningStrategy(ecdsa, jwt, ownsKey: false),
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

    internal static ISigningStrategy WrapOwned(AsymmetricAlgorithm key, string algorithm, HashAlgorithmName? pssHash)
    {
        return key switch
        {
            RSA rsa => new PrivateKeySigningStrategy(rsa, algorithm, ownsKey: true, pssHash),
            ECDsa ecdsa => new PrivateKeySigningStrategy(ecdsa, algorithm, ownsKey: true),
            _ => throw new SmartTokenException("Tipo de chave n\u00e3o suportado: " + key.GetType().Name),
        };
    }

    private static string MapJwtAlgorithmToLegacyIdentifier(string jwtAlgorithm)
    {
        return jwtAlgorithm switch
        {
            "RS256" => "SHA256withRSA",
            "RS384" => "SHA384withRSA",
            "RS512" => "SHA512withRSA",
            "PS256" or "PS384" or "PS512" => "RSASSA-PSS",
            "ES256" => "SHA256withECDSAinP1363Format",
            "ES384" => "SHA384withECDSAinP1363Format",
            "ES512" => "SHA512withECDSAinP1363Format",
            _ => jwtAlgorithm,
        };
    }
}
