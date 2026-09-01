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
    /// <summary>Algoritmo JCA padrão para chaves RSA (<c>SHA384withRSA</c> / RS384).</summary>
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
    public PrivateKeySigningStrategy(RSA privateKey)
        : this(privateKey, DefaultAlgorithm, ownsKey: false, pssHash: null)
    {
    }

    /// <summary>
    /// Cria estratégia RSA com algoritmo JCA explícito; a chave permanece sob controle do chamador.
    /// </summary>
    /// <param name="privateKey">Chave privada RSA.</param>
    /// <param name="algorithm">Nome JCA (ex.: <c>SHA384withRSA</c>).</param>
    public PrivateKeySigningStrategy(RSA privateKey, string algorithm)
        : this(privateKey, algorithm, ownsKey: false, pssHash: null)
    {
    }

    /// <summary>
    /// Cria estratégia ECDSA com algoritmo JCA explícito; a chave permanece sob controle do chamador.
    /// </summary>
    /// <param name="privateKey">Chave privada ECDSA.</param>
    /// <param name="algorithm">Nome JCA (ex.: <c>SHA384withECDSAinP1363Format</c>).</param>
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

    /// <summary>Nome JCA configurado para assinatura.</summary>
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

            if (IsRsaJcaName(Algorithm))
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
        if (algorithm.Equals("RSASSA-PSS", StringComparison.OrdinalIgnoreCase))
        {
            if (pssHash is null)
            {
                throw new SigningException(
                    "Falha ao assinar dados com algoritmo " + algorithm,
                    new InvalidOperationException("RSASSA-PSS exige hash PSS."));
            }

            return (pssHash.Value, RSASignaturePadding.Pss);
        }

        return algorithm switch
        {
            "SHA256withRSA" => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "SHA384withRSA" => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            "SHA512withRSA" => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            _ => throw new CryptographicException("Algoritmo n\u00e3o reconhecido: " + algorithm),
        };
    }

    private static bool IsRsaJcaName(string algorithm)
    {
        return algorithm.Contains("RSA", StringComparison.OrdinalIgnoreCase)
            || algorithm.Equals("RSASSA-PSS", StringComparison.OrdinalIgnoreCase);
    }

    private static HashAlgorithmName ResolveEcdsaHash(string algorithm)
    {
        if (algorithm.Contains("SHA512", StringComparison.OrdinalIgnoreCase))
        {
            return HashAlgorithmName.SHA512;
        }

        if (algorithm.Contains("SHA384", StringComparison.OrdinalIgnoreCase))
        {
            return HashAlgorithmName.SHA384;
        }

        return HashAlgorithmName.SHA256;
    }
}
