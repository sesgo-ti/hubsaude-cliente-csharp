// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HubSaude.Cliente;

/// <summary>
/// Validações fail-fast de consistência entre o material de assinatura (chave privada ou
/// <see cref="ISigningStrategy"/>) e o certificado X.509 do cliente.
/// </summary>
/// <remarks>
/// <para>
/// A verificação realiza uma assinatura de teste e a confere com a chave pública extraída
/// do certificado. Assim, erros de configuração (arquivos trocados, chave corrompida,
/// certificado regenerado sem atualizar a chave) são detectados na inicialização, e não
/// apenas quando o authorization server rejeitar o <c>client_assertion</c>.
/// </para>
/// </remarks>
internal static class KeyCertificateConsistency
{
    /// <summary>Dados de desafio usados na assinatura de teste (idêntico ao cliente Java).</summary>
    internal static readonly byte[] Challenge = Encoding.UTF8.GetBytes("key-pair-consistency-check");

    /// <summary>
    /// Verifica que a chave privada corresponde à chave pública do certificado, assinando
    /// um desafio e conferindo a assinatura.
    /// </summary>
    /// <param name="privateKey">Chave privada a validar.</param>
    /// <param name="certificate">Certificado X.509 contendo a chave pública correspondente.</param>
    /// <exception cref="SmartTokenException">
    /// Se a assinatura de teste falhar, indicando que chave e certificado não formam um par válido.
    /// </exception>
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

    /// <summary>
    /// Verifica que a estratégia de assinatura é consistente com o certificado do cliente.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A assinatura de teste é produzida pela própria estratégia (o que funciona inclusive
    /// para HSM, pois a assinatura é delegada ao hardware) e verificada com a chave pública
    /// do certificado, usando o mesmo algoritmo e parâmetros da estratégia.
    /// </para>
    /// <para>
    /// <strong>Limitação:</strong> a verificação só é possível quando a estratégia é uma
    /// <see cref="PrivateKeySigningStrategy"/>, pois é necessário conhecer o algoritmo para
    /// verificar a assinatura. Estratégias customizadas são aceitas sem validação.
    /// </para>
    /// </remarks>
    /// <param name="strategy">Estratégia de assinatura a validar.</param>
    /// <param name="certificate">Certificado X.509 com a chave pública correspondente.</param>
    /// <exception cref="SmartTokenException">
    /// Se a assinatura de teste não puder ser verificada com a chave pública do certificado.
    /// </exception>
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
