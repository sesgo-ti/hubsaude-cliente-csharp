// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente;

internal sealed class TlsSettings
{
    private string? _certificatePem;
    private string? _serverTrustAnchorPath;
    private X509Certificate2? _serverTrustAnchorCert;
    private HttpMessageHandler? _customHandler;
    private X509Certificate2? _clientCertificate;
    private string _tlsProtocol = SmartTokenClient.DefaultTlsProtocol;

    internal void SetCertificatePem(string certificatePem)
    {
        _certificatePem = certificatePem;
    }

    internal void SetServerTrustAnchorPath(string? serverTrustAnchor)
    {
        _serverTrustAnchorPath = serverTrustAnchor;
    }

    internal void SetServerTrustAnchorCert(X509Certificate2? serverTrustAnchorCert)
    {
        _serverTrustAnchorCert = serverTrustAnchorCert;
    }

    internal void SetCustomHandler(HttpMessageHandler customHandler)
    {
        _customHandler = customHandler;
    }

    internal void SetClientCertificate(X509Certificate2 certificate)
    {
        _clientCertificate = certificate;
    }

    internal void SetTlsProtocol(string tlsProtocol)
    {
        _tlsProtocol = tlsProtocol;
    }

    internal string TlsProtocol => _tlsProtocol;

    internal HttpMessageHandler? CustomHandler => _customHandler;

    internal X509Certificate2? LoadCertificate()
    {
        return _certificatePem is null
            ? null
            : CertificateValidator.ValidateFromPemFile(_certificatePem);
    }

    internal HttpMessageHandler ResolveHandler(
        TimeSpan connectTimeout,
        AsymmetricAlgorithm? clientKey,
        X509Certificate2? clientCert)
    {
        if (_customHandler is not null)
        {
            return _customHandler;
        }

        var trustAnchor = LoadTrustAnchor();
        var mtlsCert = ResolveClientCertificate(clientKey, clientCert);
        return SslOptionsFactory.CreateHandler(connectTimeout, _tlsProtocol, trustAnchor, mtlsCert);
    }

    internal X509Certificate2? ResolveClientCertificate(
        AsymmetricAlgorithm? clientKey,
        X509Certificate2? clientCert)
    {
        if (_clientCertificate is not null)
        {
            return _clientCertificate;
        }

        if (clientCert is not null && clientCert.HasPrivateKey)
        {
            return clientCert;
        }

        if (clientKey is null || clientCert is null)
        {
            return null;
        }

        if (clientKey is RSA or ECDsa)
        {
            KeyCertificateConsistency.VerifyKeyPair(clientKey, clientCert);
        }

        return clientKey switch
        {
            RSA rsa => clientCert.CopyWithPrivateKey(rsa),
            ECDsa ecdsa => clientCert.CopyWithPrivateKey(ecdsa),
            _ => throw new SmartTokenException(
                "Tipo de chave n\u00e3o suportado para mTLS: " + clientKey.GetType().Name),
        };
    }

    private X509Certificate2? LoadTrustAnchor()
    {
        if (_serverTrustAnchorCert is not null)
        {
            CertificateValidator.CheckValidity(_serverTrustAnchorCert, _serverTrustAnchorCert.Subject);
            return _serverTrustAnchorCert;
        }

        if (_serverTrustAnchorPath is not null)
        {
            return CertificateValidator.ValidateFromPemFile(_serverTrustAnchorPath);
        }

        return null;
    }
}
