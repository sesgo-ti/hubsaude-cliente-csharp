// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;

namespace HubSaude.Cliente;

/// <summary>
/// Implementação de <see cref="ISigningStrategy"/> baseada em RSA ou ECDSA (RF-12, RF-16).
/// Thread-safe: cada Sign usa a API thread-safe do algoritmo.
/// </summary>
public sealed class PrivateKeySigningStrategy : ISigningStrategy, IDisposable
{
    /// <summary>
    /// Algoritmo de assinatura padrão para chaves RSA: equivalente a <c>RS384</c>
    /// (PKCS#1 v1.5 com SHA-384). Novos chamadores devem passar o alg JWT
    /// (<c>RS384</c>); este valor permanece para compatibilidade.
    /// </summary>
    public const string DefaultAlgorithm = "SHA384withRSA";

    private readonly RSA? _rsa;
    private readonly ECDsa? _ecdsa;
    private readonly bool _ownsKey;
    private readonly HashAlgorithmName? _pssHash;
    private bool _disposed;

    /// <summary>
    /// Cria estratégia RSA com algoritmo padrão; a chave permanece sob controle do chamador.
    /// </summary>
    /// <param name="privateKey">Chave privada RSA.</param>
    /// <exception cref="ArgumentNullException"><paramref name="privateKey"/> é nulo.</exception>
    /// <exception cref="ArgumentException">A chave está abaixo do tamanho mínimo aceito.</exception>
    public PrivateKeySigningStrategy(RSA privateKey)
        : this(privateKey, DefaultAlgorithm, ownsKey: false, pssHash: null)
    {
    }

    /// <summary>
    /// Cria estratégia RSA com algoritmo de assinatura explícito; a chave permanece sob controle do chamador.
    /// </summary>
    /// <param name="privateKey">Chave privada RSA.</param>
    /// <param name="algorithm">
    /// Algoritmo JWT (<c>RS256</c>, <c>RS384</c>, <c>RS512</c>, <c>PS256</c>,
    /// <c>PS384</c>, <c>PS512</c>) ou identificador de assinatura legado ainda aceito.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="privateKey"/> ou <paramref name="algorithm"/> é nulo.
    /// </exception>
    /// <exception cref="ArgumentException">A chave está abaixo do tamanho mínimo aceito.</exception>
    public PrivateKeySigningStrategy(RSA privateKey, string algorithm)
        : this(privateKey, algorithm, ownsKey: false, pssHash: null)
    {
    }

    /// <summary>
    /// Cria estratégia ECDSA com algoritmo de assinatura explícito; a chave permanece sob controle do chamador.
    /// </summary>
    /// <param name="privateKey">Chave privada ECDSA.</param>
    /// <param name="algorithm">
    /// Algoritmo JWT (<c>ES256</c>, <c>ES384</c>, <c>ES512</c>) ou identificador
    /// de assinatura legado ainda aceito.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="privateKey"/> ou <paramref name="algorithm"/> é nulo.
    /// </exception>
    /// <exception cref="ArgumentException">A chave está abaixo do tamanho mínimo aceito.</exception>
    public PrivateKeySigningStrategy(ECDsa privateKey, string algorithm)
        : this(privateKey, algorithm, ownsKey: false)
    {
    }

    internal PrivateKeySigningStrategy(RSA privateKey, string algorithm, bool ownsKey, HashAlgorithmName? pssHash)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(algorithm);
        PemLoader.ValidateMinimumKeySize(privateKey, "privateKey");

        _rsa = privateKey;
        _ownsKey = ownsKey;
        _pssHash = pssHash;
        Algorithm = algorithm;
    }

    internal PrivateKeySigningStrategy(ECDsa privateKey, string algorithm, bool ownsKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(algorithm);
        PemLoader.ValidateMinimumKeySize(privateKey, "privateKey");

        _ecdsa = privateKey;
        _ownsKey = ownsKey;
        Algorithm = algorithm;
    }

    /// <summary>Identificador do algoritmo de assinatura configurado.</summary>
    public string Algorithm { get; }

    internal HashAlgorithmName HashAlgorithm =>
        _rsa is not null ? ResolveRsa(Algorithm, _pssHash).Hash : ResolveEcdsaHash(Algorithm);

    internal RSASignaturePadding? RsaPadding =>
        _rsa is not null ? ResolveRsa(Algorithm, _pssHash).Padding : null;

    /// <inheritdoc />
    public byte[] Sign(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            if (_rsa is not null)
            {
                var (hash, padding) = ResolveRsa(Algorithm, _pssHash);
                return _rsa.SignData(data, hash, padding);
            }

            if (IsRsaAlgorithm(Algorithm))
            {
                throw new SigningException("Falha ao assinar dados com algoritmo " + Algorithm);
            }

            return _ecdsa!.SignData(
                data, ResolveEcdsaHash(Algorithm), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException ex)
        {
            throw new SigningException("Falha ao assinar dados com algoritmo " + Algorithm, ex);
        }
    }

    /// <summary>
    /// Libera a chave privada quando esta instância assumiu ownership (<c>ownsKey</c>).
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_ownsKey)
        {
            _rsa?.Dispose();
            _ecdsa?.Dispose();
        }
    }

    private static (HashAlgorithmName Hash, RSASignaturePadding Padding) ResolveRsa(
        string algorithm,
        HashAlgorithmName? pssHash)
    {
        var name = algorithm.ToUpperInvariant();
        if (name.Equals("RSASSA-PSS", StringComparison.Ordinal))
        {
            if (pssHash is null)
            {
                throw new SigningException(
                    "Falha ao assinar dados com algoritmo " + algorithm,
                    new InvalidOperationException("RSASSA-PSS exige hash PSS."));
            }

            return (pssHash.Value, RSASignaturePadding.Pss);
        }

        return name switch
        {
            "RS256" or "SHA256WITHRSA" => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "RS384" or "SHA384WITHRSA" => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            "RS512" or "SHA512WITHRSA" => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            "PS256" => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            "PS384" => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
            "PS512" => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
            _ => throw new CryptographicException("Algoritmo n\u00e3o reconhecido: " + algorithm),
        };
    }

    private static bool IsRsaAlgorithm(string algorithm)
    {
        var name = algorithm.ToUpperInvariant();
        return name is "RS256" or "RS384" or "RS512" or "PS256" or "PS384" or "PS512"
            or "RSASSA-PSS"
            || name.Contains("RSA", StringComparison.Ordinal);
    }

    private static HashAlgorithmName ResolveEcdsaHash(string algorithm)
    {
        var name = algorithm.ToUpperInvariant();
        return name switch
        {
            "ES256" or "SHA256WITHECDSAINP1363FORMAT" => HashAlgorithmName.SHA256,
            "ES384" or "SHA384WITHECDSAINP1363FORMAT" => HashAlgorithmName.SHA384,
            "ES512" or "SHA512WITHECDSAINP1363FORMAT" => HashAlgorithmName.SHA512,
            _ when name.Contains("SHA512", StringComparison.Ordinal) => HashAlgorithmName.SHA512,
            _ when name.Contains("SHA384", StringComparison.Ordinal) => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA256,
        };
    }
}
