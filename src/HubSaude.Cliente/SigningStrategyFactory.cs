// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente;

/// <summary>
/// Parâmetros PSS equivalentes ao PSSParameterSpec do Java (RFC 7518 §3.5).
/// </summary>
public sealed record PssParameters(string DigestAlgorithm, int SaltLength);

/// <summary>
/// Factory de <see cref="ISigningStrategy"/> (RF-12, RF-16).
/// </summary>
public static class SigningStrategyFactory
{
    private const string ValidAlgorithms =
        "RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512";

    public static ISigningStrategy FromPrivateKey(RSA privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        return new PrivateKeySigningStrategy(privateKey);
    }

    public static ISigningStrategy FromPrivateKey(RSA privateKey, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(algorithm);
        return new PrivateKeySigningStrategy(privateKey, algorithm);
    }

    public static ISigningStrategy FromPrivateKey(ECDsa privateKey, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(algorithm);
        return new PrivateKeySigningStrategy(privateKey, algorithm);
    }

    public static ISigningStrategy FromPemFile(string keyPath)
    {
        return FromPemFile(keyPath, password: null);
    }

    public static ISigningStrategy FromPemFile(string keyPath, char[]? password)
    {
        ArgumentNullException.ThrowIfNull(keyPath);
        var key = PemLoader.LoadPrivateKey(keyPath, password);
        return WrapOwned(key, PrivateKeySigningStrategy.DefaultAlgorithm, pssHash: null);
    }

    public static ISigningStrategy FromPemString(string pemContent, char[]? password)
    {
        ArgumentNullException.ThrowIfNull(pemContent);
        var key = PemLoader.LoadPrivateKeyFromString(pemContent, password, "<string>");
        return WrapOwned(key, PrivateKeySigningStrategy.DefaultAlgorithm, pssHash: null);
    }

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

    public static ISigningStrategy FromPkcs12(byte[] pkcs12, string alias, char[]? password)
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

            return FromCertificate(match);
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
