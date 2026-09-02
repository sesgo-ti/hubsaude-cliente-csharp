// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente;

/// <summary>
/// Constrói opções TLS/mTLS para <see cref="SocketsHttpHandler"/>.
/// </summary>
/// <remarks>
/// <para>
/// Centraliza a lógica de configuração SSL/TLS e validação de certificados X.509,
/// mantendo <see cref="SmartTokenClient"/> focado na lógica de aquisição de tokens.
/// </para>
/// <para>
/// Modos de operação: trust store do sistema quando nenhum trust anchor é fornecido;
/// trust anchor específico via certificado PEM do servidor para validação TLS customizada.
/// </para>
/// </remarks>
internal static class SslOptionsFactory
{
    /// <summary>Converte o identificador de protocolo TLS em <see cref="SslProtocols"/>.</summary>
    /// <param name="tlsProtocol">Protocolo TLS (ex.: TLSv1.3, Tls12, TLS).</param>
    /// <returns>Protocolos SSL habilitados.</returns>
    /// <exception cref="SmartTokenException">Quando o protocolo não é suportado.</exception>
    internal static SslProtocols ParseProtocol(string tlsProtocol)
    {
        ArgumentNullException.ThrowIfNull(tlsProtocol);
        return tlsProtocol switch
        {
            "TLSv1.3" or "Tls13" => SslProtocols.Tls13,
            "TLSv1.2" or "Tls12" => SslProtocols.Tls12,
            "TLS" => SslProtocols.Tls12 | SslProtocols.Tls13,
            _ => throw new SmartTokenException("Protocolo TLS n\u00e3o suportado: " + tlsProtocol),
        };
    }

    /// <summary>
    /// Aplica protocolo TLS, trust anchor e certificado de cliente nas opções SSL.
    /// </summary>
    internal static void Configure(
        SslClientAuthenticationOptions options,
        string tlsProtocol,
        X509Certificate2? serverTrustAnchor,
        X509Certificate2? clientCertificate)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.EnabledSslProtocols = ParseProtocol(tlsProtocol);

        if (serverTrustAnchor is not null)
        {
            CertificateValidator.CheckValidity(
                serverTrustAnchor,
                serverTrustAnchor.Subject);
            var anchor = serverTrustAnchor;
            options.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                ValidateAgainstAnchor(certificate, anchor);
        }

        if (clientCertificate is not null)
        {
            CertificateValidator.CheckValidity(clientCertificate, clientCertificate.Subject);
            if (!clientCertificate.HasPrivateKey)
            {
                throw new SmartTokenException(
                    "Certificado de cliente para mTLS n\u00e3o cont\u00e9m chave privada: "
                    + clientCertificate.Subject);
            }

            options.ClientCertificates = [clientCertificate];
            options.LocalCertificateSelectionCallback = (_, _, _, _, _) => clientCertificate;
        }
    }

    /// <summary>
    /// Cria um <see cref="SocketsHttpHandler"/> com timeout de conexão e TLS/mTLS configurados.
    /// </summary>
    internal static SocketsHttpHandler CreateHandler(
        TimeSpan connectTimeout,
        string tlsProtocol,
        X509Certificate2? serverTrustAnchor,
        X509Certificate2? clientCertificate)
    {
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = connectTimeout,
        };
        Configure(handler.SslOptions, tlsProtocol, serverTrustAnchor, clientCertificate);
        return handler;
    }

    private static bool ValidateAgainstAnchor(X509Certificate? certificate, X509Certificate2 trustAnchor)
    {
        if (certificate is null)
        {
            return false;
        }

        using var presented = new X509Certificate2(certificate);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(trustAnchor);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(presented);
    }
}
