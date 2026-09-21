// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente;

/// <summary>
/// Carrega PKCS#12 para mTLS/assinatura com flags que o stack TLS da plataforma aceita.
/// No Windows, o Schannel exige chave no store do usuário; nos demais SOs usa conjunto efêmero.
/// </summary>
internal static class Pkcs12KeyStorage
{
    /// <summary>
    /// Flags de persistência da chave privada compatíveis com o TLS da plataforma.
    /// </summary>
    internal static X509KeyStorageFlags MtlsFlags()
    {
        return OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable
            : X509KeyStorageFlags.EphemeralKeySet;
    }

    /// <summary>
    /// Materializa chave PEM + certificado em um PKCS#12 e reimporta para mTLS.
    /// </summary>
    internal static X509Certificate2 FromKeyAndCertificate(AsymmetricAlgorithm clientKey, X509Certificate2 clientCert)
    {
        ArgumentNullException.ThrowIfNull(clientKey);
        ArgumentNullException.ThrowIfNull(clientCert);

        if (clientKey is RSA or ECDsa)
        {
            KeyCertificateConsistency.VerifyKeyPair(clientKey, clientCert);
        }

        X509Certificate2? publicOnly = null;
        var certWithoutKey = clientCert;
        if (clientCert.HasPrivateKey)
        {
            publicOnly = X509CertificateLoader.LoadCertificate(clientCert.RawData);
            certWithoutKey = publicOnly;
        }

        X509Certificate2 combined;
        try
        {
            combined = clientKey switch
            {
                RSA rsa => BindRsaCopy(certWithoutKey, rsa),
                ECDsa ecdsa => BindEcdsaCopy(certWithoutKey, ecdsa),
                _ => throw new SmartTokenException(
                    "Tipo de chave n\u00e3o suportado para mTLS: " + clientKey.GetType().Name),
            };
        }
        finally
        {
            publicOnly?.Dispose();
        }

        using (combined)
        {
            var alias = combined.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (string.IsNullOrWhiteSpace(alias))
            {
                alias = "client";
            }

            var passwordChars = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToCharArray();
            var password = new string(passwordChars);
            byte[] pfx;
            try
            {
                pfx = combined.Export(X509ContentType.Pkcs12, password);
            }
            finally
            {
                PemLoader.ClearPassword(passwordChars);
            }

            try
            {
                return LoadCertificate(pfx, alias, password.ToCharArray());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pfx);
            }
        }
    }

    private static X509Certificate2 BindRsaCopy(X509Certificate2 clientCert, RSA rsa)
    {
        var copy = RSA.Create();
        try
        {
            copy.ImportParameters(rsa.ExportParameters(includePrivateParameters: true));
            return clientCert.CopyWithPrivateKey(copy);
        }
        catch
        {
            copy.Dispose();
            throw;
        }
    }

    private static X509Certificate2 BindEcdsaCopy(X509Certificate2 clientCert, ECDsa ecdsa)
    {
        var copy = ECDsa.Create();
        try
        {
            copy.ImportParameters(ecdsa.ExportParameters(includePrivateParameters: true));
            return clientCert.CopyWithPrivateKey(copy);
        }
        catch
        {
            copy.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Seleciona o certificado com chave privada cujo alias coincide com o informado.
    /// </summary>
    internal static X509Certificate2 LoadCertificate(byte[] pkcs12, string alias, char[]? password)
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
                MtlsFlags());

            X509Certificate2? match = null;
            foreach (var cert in collection)
            {
                if (match is null && cert.HasPrivateKey && MatchesAlias(cert, alias))
                {
                    match = cert;
                    continue;
                }

                cert.Dispose();
            }

            if (match is null)
            {
                throw new SmartTokenException("Chave n\u00e3o encontrada no PKCS#12: " + alias);
            }

            CertificateValidator.CheckValidity(match, match.Subject);
            return match;
        }
        catch (SmartTokenException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SmartTokenException("Falha ao carregar PKCS#12: " + ex.Message, ex);
        }
        finally
        {
            PemLoader.ClearPassword(passwordCopy);
        }
    }

    internal static bool MatchesAlias(X509Certificate2 cert, string alias)
    {
        if (string.Equals(cert.FriendlyName, alias, StringComparison.Ordinal))
        {
            return true;
        }

        var simple = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        return string.Equals(simple, alias, StringComparison.Ordinal);
    }
}
