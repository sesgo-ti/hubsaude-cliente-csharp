// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HubSaude.Cliente;

const string tls = "TLSv1.2";
const string defaultFhir = "https://hub-homolog.saude.go.gov.br/";
const string defaultScope = "system/Patient.rs";
const string defaultIg = "hemograma";
const string defaultIgVersao = "0.0.1";

var clientId = Environment.GetEnvironmentVariable("HOMOLOG_CLIENT_ID");
var certPath = Environment.GetEnvironmentVariable("HOMOLOG_CERT_PATH");
var keyPath = Environment.GetEnvironmentVariable("HOMOLOG_KEY_PATH");
var pfxPath = Environment.GetEnvironmentVariable("HOMOLOG_PFX_PATH");
var pfxAlias = Environment.GetEnvironmentVariable("HOMOLOG_PFX_ALIAS");
var pfxPassword = Environment.GetEnvironmentVariable("HOMOLOG_PFX_PASSWORD");
var fhirBase = Environment.GetEnvironmentVariable("HOMOLOG_FHIR_BASE") ?? defaultFhir;
var scope = Environment.GetEnvironmentVariable("HOMOLOG_SCOPE") ?? defaultScope;
var ig = Environment.GetEnvironmentVariable("HOMOLOG_IG") ?? defaultIg;
var igVersao = Environment.GetEnvironmentVariable("HOMOLOG_IG_VERSAO") ?? defaultIgVersao;

if (string.IsNullOrWhiteSpace(clientId)
    || (string.IsNullOrWhiteSpace(pfxPath)
        && (string.IsNullOrWhiteSpace(certPath) || string.IsNullOrWhiteSpace(keyPath))))
{
    Console.Error.WriteLine("""
        Smoke de homologação — defina as variáveis de ambiente (nenhuma credencial neste repositório):

          HOMOLOG_CLIENT_ID     (obrigatório)
          HOMOLOG_PFX_PATH      (recomendado) + HOMOLOG_PFX_ALIAS + HOMOLOG_PFX_PASSWORD
            ou
          HOMOLOG_CERT_PATH + HOMOLOG_KEY_PATH  (PEM; o SDK materializa PKCS#12 para mTLS)

          HOMOLOG_FHIR_BASE     (opcional, padrão hub-homolog)
          HOMOLOG_SCOPE         (opcional, padrão system/Patient.rs)
          HOMOLOG_IG / HOMOLOG_IG_VERSAO  (opcional, padrão hemograma / 0.0.1)
        """);
    return 2;
}

byte[]? pfxBytes = null;
char[]? pin = null;
try
{
    var builder = SmartTokenClient.CreateBuilder()
        .FhirBase(fhirBase)
        .ClientId(clientId)
        .HubContext(ig, igVersao)
        .TlsProtocol(tls);

    if (!string.IsNullOrWhiteSpace(pfxPath))
    {
        if (string.IsNullOrWhiteSpace(pfxAlias) || string.IsNullOrWhiteSpace(pfxPassword))
        {
            Console.Error.WriteLine("HOMOLOG_PFX_ALIAS e HOMOLOG_PFX_PASSWORD são obrigatórios com HOMOLOG_PFX_PATH.");
            return 2;
        }

        pfxBytes = File.ReadAllBytes(pfxPath);
        pin = pfxPassword.ToCharArray();
        builder.ClientPkcs12(pfxBytes, pfxAlias, pin);
    }
    else
    {
        builder.PrivateKeyPem(keyPath!).CertificatePem(EnsurePemCertificate(certPath!));
    }

    await using var client = await builder.BuildAsync();

    Console.WriteLine("Client ID:  " + clientId);
    Console.WriteLine("Material:   " + (string.IsNullOrWhiteSpace(pfxPath) ? "PEM (via PKCS#12 interno)" : "PKCS#12"));
    Console.WriteLine("Scope:      " + scope);
    Console.WriteLine("TLS:        " + tls);
    Console.WriteLine("IG:         " + ig + " (versão " + igVersao + ")");
    Console.WriteLine("FHIR Base:  " + fhirBase);
    Console.WriteLine("Endpoint:   " + client.TokenEndpoint);
    Console.WriteLine();
    Console.WriteLine("Obtendo token de acesso...");

    var resposta = await client.ObtainTokenResponseAsync(scope);

    Console.WriteLine("Token obtido com sucesso.");
    Console.WriteLine("expires_in: " + resposta.ExpiresIn);
    Console.WriteLine("access_token: " + resposta.AccessToken.Length + " caracteres");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message);
    if (ex.InnerException is not null)
    {
        Console.Error.WriteLine("Causa: " + ex.InnerException.Message);
    }

    return 1;
}
finally
{
    if (pin is not null)
    {
        Array.Clear(pin);
    }

    if (pfxBytes is not null)
    {
        CryptographicOperations.ZeroMemory(pfxBytes);
    }
}

static string EnsurePemCertificate(string path)
{
    var text = File.ReadAllText(path);
    if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
    {
        return path;
    }

    var cert = X509CertificateLoader.LoadCertificateFromFile(path);
    var pem = Path.Combine(Path.GetTempPath(), "hubsaude-smoke-" + Guid.NewGuid().ToString("N") + ".pem");
    File.WriteAllText(pem, cert.ExportCertificatePem());
    return pem;
}
