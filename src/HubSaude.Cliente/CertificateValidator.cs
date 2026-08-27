// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente;

/// <summary>
/// Validação fail-fast de certificados X.509 (RF-14): parse e período de validade.
/// </summary>
public static class CertificateValidator
{
    /// <summary>
    /// Carrega e valida um certificado PEM de arquivo.
    /// </summary>
    public static X509Certificate2 ValidateFromPemFile(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        var pem = File.ReadAllText(path);
        return ValidateFromPem(pem, path);
    }

    /// <summary>
    /// Carrega e valida um certificado a partir de conteúdo PEM.
    /// </summary>
    public static X509Certificate2 ValidateFromPem(string pem, string source)
    {
        ArgumentNullException.ThrowIfNull(pem);
        ArgumentNullException.ThrowIfNull(source);

        X509Certificate2 cert;
        try
        {
            cert = X509Certificate2.CreateFromPem(pem);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            throw new SmartTokenException(
                "Arquivo PEM n\u00e3o cont\u00e9m certificado X.509: " + source, ex);
        }

        CheckValidity(cert, source);
        return cert;
    }

    /// <summary>
    /// Verifica notBefore/notAfter do certificado (fail-fast).
    /// </summary>
    public static void CheckValidity(X509Certificate2 certificate, string source)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(source);

        var now = DateTime.Now;
        if (now < certificate.NotBefore)
        {
            throw new SmartTokenException("Certificado ainda n\u00e3o \u00e9 v\u00e1lido: " + source);
        }

        if (now > certificate.NotAfter)
        {
            throw new SmartTokenException("Certificado expirado: " + source);
        }
    }
}
