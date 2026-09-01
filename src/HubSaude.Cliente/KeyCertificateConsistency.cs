// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HubSaude.Cliente;

/// <summary>
/// Consistência chave-certificado (RF-15) com desafio fixo igual ao Java.
/// </summary>
internal static class KeyCertificateConsistency
{
    internal static readonly byte[] Challenge = Encoding.UTF8.GetBytes("key-pair-consistency-check");

    internal static void VerifyKeyPair(AsymmetricAlgorithm privateKey, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(certificate);

        var keyAlgorithm = GetKeyAlgorithm(privateKey);

        try
        {
            switch (keyAlgorithm)
            {
                case "RSA":
                    VerifyRsa((RSA)privateKey, certificate, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    break;
                case "EC":
                    VerifyEcdsa((ECDsa)privateKey, certificate, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
                    break;
                default:
                    throw new SmartTokenException(
                        "Tipo de chave n\u00e3o suportado para valida\u00e7\u00e3o: " + keyAlgorithm);
            }
        }
        catch (SmartTokenException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SmartTokenException(
                "Falha ao verificar consist\u00eancia entre chave privada e certificado: " + ex.Message, ex);
        }
    }

    internal static void VerifyStrategy(ISigningStrategy strategy, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(strategy);
        ArgumentNullException.ThrowIfNull(certificate);

        if (strategy is not PrivateKeySigningStrategy pkStrategy)
        {
            return;
        }

        try
        {
            var signature = pkStrategy.Sign(Challenge);
            if (pkStrategy.RsaPadding is not null)
            {
                using var rsa = certificate.GetRSAPublicKey()
                    ?? throw new SmartTokenException(
                        "Chave privada n\u00e3o corresponde ao certificado: assinatura inv\u00e1lida");
                if (!rsa.VerifyData(Challenge, signature, pkStrategy.HashAlgorithm, pkStrategy.RsaPadding))
                {
                    throw new SmartTokenException(
                        "Chave privada n\u00e3o corresponde ao certificado: assinatura inv\u00e1lida");
                }

                return;
            }

            using var ecdsa = certificate.GetECDsaPublicKey()
                ?? throw new SmartTokenException(
                    "Chave privada n\u00e3o corresponde ao certificado: assinatura inv\u00e1lida");
            if (!ecdsa.VerifyData(
                    Challenge,
                    signature,
                    pkStrategy.HashAlgorithm,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                throw new SmartTokenException(
                    "Chave privada n\u00e3o corresponde ao certificado: assinatura inv\u00e1lida");
            }
        }
        catch (SmartTokenException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SmartTokenException(
                "Falha ao verificar consist\u00eancia entre chave privada e certificado: " + ex.Message, ex);
        }
    }

    private static string GetKeyAlgorithm(AsymmetricAlgorithm privateKey) =>
        privateKey switch
        {
            RSA => "RSA",
            ECDsa => "EC",
            DSA => "DSA",
            _ => privateKey.GetType().Name
        };

    private static void VerifyRsa(
        RSA privateKey,
        X509Certificate2 certificate,
        HashAlgorithmName hash,
        RSASignaturePadding padding)
    {
        var signature = privateKey.SignData(Challenge, hash, padding);
        using var publicKey = certificate.GetRSAPublicKey()
            ?? throw new SmartTokenException(
                "Chave privada n\u00e3o corresponde ao certificado: assinatura inv\u00e1lida");
        if (!publicKey.VerifyData(Challenge, signature, hash, padding))
        {
            throw new SmartTokenException(
                "Chave privada n\u00e3o corresponde ao certificado: assinatura inv\u00e1lida");
        }
    }

    private static void VerifyEcdsa(
        ECDsa privateKey,
        X509Certificate2 certificate,
        HashAlgorithmName hash,
        DSASignatureFormat format)
    {
        var signature = privateKey.SignData(Challenge, hash, format);
        using var publicKey = certificate.GetECDsaPublicKey()
            ?? throw new SmartTokenException(
                "Chave privada n\u00e3o corresponde ao certificado: assinatura inv\u00e1lida");
        if (!publicKey.VerifyData(Challenge, signature, hash, format))
        {
            throw new SmartTokenException(
                "Chave privada n\u00e3o corresponde ao certificado: assinatura inv\u00e1lida");
        }
    }
}
