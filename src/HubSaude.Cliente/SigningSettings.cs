// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente;

/// <summary>
/// Agrupa a configuração de assinatura do <c>client_assertion</c> JWT do
/// <see cref="SmartTokenClientBuilder"/> e resolve a <see cref="ISigningStrategy"/>
/// efetiva a partir dela.
/// </summary>
/// <remarks>
/// <para>
/// Colaborador interno do <see cref="SmartTokenClientBuilder"/>, extraído para
/// reduzir o número de campos e a complexidade de <c>Build()</c>.
/// Não faz parte da API pública da biblioteca: os valores são definidos
/// exclusivamente pelos métodos fluentes do builder.
/// </para>
/// <para>
/// As fontes de assinatura são mutuamente exclusivas: ou uma
/// <see cref="ISigningStrategy"/> própria (HSM, cofre de segredos) ou material
/// em arquivo PEM/PKCS#12, da qual a estratégia é derivada conforme o algoritmo
/// JWT configurado.
/// </para>
/// </remarks>
internal sealed class SigningSettings
{
    private string? _privateKeyPem;
    private char[]? _privateKeyPassword;
    private ISigningStrategy? _signingStrategy;
    private byte[]? _pkcs12;
    private string? _pkcs12Alias;
    private char[]? _pkcs12Password;
    private string _jwtAlgorithm = SmartTokenClient.DefaultJwtAlgorithm;
    private string? _keyId;

    internal void SetPrivateKeyPem(string privateKeyPem)
    {
        _privateKeyPem = privateKeyPem;
    }

    internal void SetPrivateKeyPassword(char[]? privateKeyPassword)
    {
        _privateKeyPassword = privateKeyPassword;
    }

    internal void SetSigningStrategy(ISigningStrategy signingStrategy)
    {
        _signingStrategy = signingStrategy;
    }

    internal void SetPkcs12(byte[] pkcs12, string alias, char[]? password)
    {
        _pkcs12 = pkcs12;
        _pkcs12Alias = alias;
        _pkcs12Password = password;
    }

    internal void SetJwtAlgorithm(string jwtAlgorithm)
    {
        _jwtAlgorithm = jwtAlgorithm;
    }

    internal void SetKeyId(string keyId)
    {
        _keyId = keyId;
    }

    internal string JwtAlgorithm => _jwtAlgorithm;

    /// <summary>Identificador da chave (<c>kid</c>) no header do JWT; opcional.</summary>
    internal string? KeyId => _keyId;

    /// <summary>
    /// Resolve a estratégia de assinatura efetiva, validando a exclusividade mútua entre
    /// <see cref="ISigningStrategy"/>, chave PEM e PKCS#12.
    /// </summary>
    /// <returns>Estratégia efetiva e, quando aplicável, chave/certificado para mTLS.</returns>
    /// <exception cref="InvalidOperationException">
    /// Quando fontes de assinatura conflitantes ou nenhuma foi definida.
    /// </exception>
    internal Resolved Resolve()
    {
        var sources = 0;
        if (_signingStrategy is not null)
        {
            sources++;
        }

        if (_privateKeyPem is not null)
        {
            sources++;
        }

        if (_pkcs12 is not null)
        {
            sources++;
        }

        if (sources > 1)
        {
            throw new InvalidOperationException(
                "Defina signingStrategy OU privateKeyPem OU clientPkcs12, n\u00e3o combina\u00e7\u00f5es");
        }

        if (_signingStrategy is not null)
        {
            return new Resolved(_signingStrategy, ClientKey: null, ClientCertificate: null);
        }

        if (_pkcs12 is not null)
        {
            var cert = SigningStrategyFactory.LoadPkcs12Certificate(_pkcs12, _pkcs12Alias!, _pkcs12Password);
            return new Resolved(
                SigningStrategyFactory.FromCertificate(cert),
                ClientKey: null,
                cert);
        }

        if (_privateKeyPem is null)
        {
            throw new InvalidOperationException(
                "\u00c9 obrigat\u00f3rio definir signingStrategy ou privateKeyPem");
        }

        var clientKey = PemLoader.LoadPrivateKey(_privateKeyPem, _privateKeyPassword);
        return new Resolved(
            SigningStrategyFactory.FromPrivateKeyForJwt(clientKey, _jwtAlgorithm),
            clientKey,
            ClientCertificate: null);
    }

    /// <summary>
    /// Zera e descarta senhas e buffers PKCS#12, minimizando a exposição de segredos em memória
    /// após a construção do cliente.
    /// </summary>
    internal void ClearSecrets()
    {
        PemLoader.ClearPassword(_privateKeyPassword);
        _privateKeyPassword = null;
        PemLoader.ClearPassword(_pkcs12Password);
        _pkcs12Password = null;
        if (_pkcs12 is not null)
        {
            CryptographicOperations.ZeroMemory(_pkcs12);
            _pkcs12 = null;
        }
    }

    /// <summary>
    /// Resultado da resolução da configuração de assinatura.
    /// </summary>
    /// <param name="Strategy">Estratégia de assinatura efetiva do <c>client_assertion</c>.</param>
    /// <param name="ClientKey">
    /// Chave privada carregada do PEM, disponível para mTLS; <c>null</c> quando a estratégia
    /// foi fornecida diretamente (HSM, cofre) ou veio de PKCS#12.
    /// </param>
    /// <param name="ClientCertificate">
    /// Certificado carregado de PKCS#12, quando aplicável.
    /// </param>
    internal sealed record Resolved(
        ISigningStrategy Strategy,
        AsymmetricAlgorithm? ClientKey,
        X509Certificate2? ClientCertificate);
}
