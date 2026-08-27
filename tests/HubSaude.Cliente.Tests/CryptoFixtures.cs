// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace HubSaude.Cliente.Tests;

internal static class CryptoFixtures
{
    internal static RSA CreateRsa(int keySize = 2048)
    {
        return RSA.Create(keySize);
    }

    internal static ECDsa CreateP256()
    {
        return ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    internal static string ToPkcs8Pem(RSA rsa)
    {
        return rsa.ExportPkcs8PrivateKeyPem();
    }

    internal static string ToPkcs8Pem(ECDsa ecdsa)
    {
        return ecdsa.ExportPkcs8PrivateKeyPem();
    }

    internal static string ToPkcs1Pem(RSA rsa)
    {
        return rsa.ExportRSAPrivateKeyPem();
    }

    internal static string ToEncryptedPkcs8Pem(RSA rsa, string password)
    {
        return rsa.ExportEncryptedPkcs8PrivateKeyPem(
            password,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));
    }

    internal static string ToOpenSslEncryptedPem(RSA rsa, string password)
    {
        var pair = DotNetUtilities.GetRsaKeyPair(rsa.ExportParameters(includePrivateParameters: true));
        using var writer = new StringWriter();
        var pemWriter = new PemWriter(writer);
        pemWriter.WriteObject(pair.Private, "DES-EDE3-CBC", password.ToCharArray(), new SecureRandom());
        pemWriter.Writer.Flush();
        return writer.ToString();
    }

    internal static string SelfSignedPem(
        RSA rsa,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        string cn = "test-client")
    {
        var request = new CertificateRequest(
            $"C=BR, O=Test, CN={cn}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(notBefore, notAfter);
        return cert.ExportCertificatePem();
    }

    internal static X509Certificate2 SelfSignedCert(RSA rsa, string cn = "test-alias")
    {
        var request = new CertificateRequest(
            $"CN={cn}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
    }

    internal static X509Certificate2 SelfSignedCert(ECDsa ecdsa, string cn = "test-client")
    {
        var request = new CertificateRequest(
            $"CN={cn}",
            ecdsa,
            HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
    }

    internal static string WriteTemp(string contents, string extension = ".pem")
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + extension);
        File.WriteAllText(path, contents);
        return path;
    }
}
