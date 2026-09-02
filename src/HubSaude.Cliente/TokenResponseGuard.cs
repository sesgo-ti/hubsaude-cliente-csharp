// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace HubSaude.Cliente;

/// <summary>
/// Salvaguardas de sanidade para a resposta do token endpoint: validação/normalização
/// do campo <c>expires_in</c> e leitura do corpo HTTP com teto de tamanho.
/// </summary>
/// <remarks>
/// <para>
/// Ambas as proteções mitigam um servidor de autorização comprometido ou malicioso:
/// um <c>expires_in</c> adulterado não pode reter tokens no cache além do teto de
/// sanidade, e uma resposta gigante não pode consumir memória sem limite.
/// </para>
/// </remarks>
internal static class TokenResponseGuard
{
    /// <summary>
    /// Valor assumido para <c>expires_in</c> (segundos) quando ausente na resposta —
    /// campo opcional na RFC 6749 §5.1; 1 hora é o valor usual em servidores SMART.
    /// </summary>
    internal const int DefaultExpiresInSeconds = 3600;

    /// <summary>
    /// Teto de sanidade para <c>expires_in</c> (24h). Valores acima são normalizados
    /// antes de alimentar o cache de tokens.
    /// </summary>
    internal const int MaxExpiresInSeconds = 86_400;

    /// <summary>
    /// Limite (bytes) do corpo da resposta do token endpoint: 1 MiB.
    /// Respostas legítimas têm poucos KiB; acima disso a leitura é abortada com erro claro.
    /// </summary>
    internal const long MaxResponseBodyBytes = 1_048_576L;

    /// <summary>
    /// Aplica a política de sanidade ao campo <c>expires_in</c>.
    /// </summary>
    /// <param name="node">Nó raiz da resposta JSON do token endpoint.</param>
    /// <param name="logger">Logger opcional para mensagens de debug/aviso.</param>
    /// <returns>Valor saneado de <c>expires_in</c>, em segundos.</returns>
    /// <exception cref="SmartTokenException">
    /// Quando o valor é zero, negativo ou não numérico.
    /// </exception>
    internal static int SanitizeExpiresIn(JsonElement node, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;
        if (!node.TryGetProperty("expires_in", out var expires))
        {
            logger.LogDebug("Resposta sem 'expires_in' \u2014 assumindo padr\u00e3o de {Seconds}s", DefaultExpiresInSeconds);
            return DefaultExpiresInSeconds;
        }

        if (!TryReadExpiresIn(expires, out var value) || value <= 0)
        {
            throw new SmartTokenException(
                "'expires_in' inv\u00e1lido na resposta do token endpoint: "
                + expires.GetRawText()
                + " (esperado inteiro em 0 < x <= " + MaxExpiresInSeconds + ")");
        }

        if (value > MaxExpiresInSeconds)
        {
            logger.LogWarning(
                "'expires_in'={Value}s acima do teto de sanidade \u2014 normalizando para {Max}s",
                value,
                MaxExpiresInSeconds);
            return MaxExpiresInSeconds;
        }

        return (int)value;
    }

    private static bool TryReadExpiresIn(JsonElement expires, out long value)
    {
        if (expires.ValueKind == JsonValueKind.Number && expires.TryGetInt64(out value))
        {
            return true;
        }

        if (expires.ValueKind == JsonValueKind.String && long.TryParse(expires.GetString(), out value))
        {
            return true;
        }

        value = 0;
        return false;
    }

    /// <summary>
    /// Lê o corpo da resposta como string UTF-8, impondo o teto de <paramref name="maxBytes"/>.
    /// </summary>
    /// <param name="response">Resposta HTTP cujo corpo será lido.</param>
    /// <param name="maxBytes">Limite máximo do corpo, em bytes.</param>
    /// <param name="cancellationToken">Token de cancelamento.</param>
    /// <returns>Corpo da resposta como string UTF-8.</returns>
    /// <exception cref="SmartTokenException">
    /// Quando o <c>Content-Length</c> declarado ou os bytes recebidos excedem o limite.
    /// </exception>
    internal static async Task<string> ReadBoundedStringAsync(
        HttpResponseMessage response,
        long maxBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.Content.Headers.ContentLength is { } declared && declared > maxBytes)
        {
            throw BodyLimitExceeded(declared, maxBytes);
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        long received = 0;
        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            received += read;
            if (received > maxBytes)
            {
                throw BodyLimitExceeded(received, maxBytes);
            }

            buffer.Write(chunk, 0, read);
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// Desembrulha a violação do limite de corpo quando reportada envolvida em outra exceção;
    /// caso contrário devolve a exceção original para tratamento normal (retry, heurísticas de TLS).
    /// </summary>
    /// <param name="ex">Exceção capturada durante a leitura da resposta.</param>
    /// <returns>A própria exceção, quando não relacionada ao limite de corpo.</returns>
    /// <exception cref="SmartTokenException">Quando a causa raiz é o estouro do limite.</exception>
    internal static Exception UnwrapBodyLimitViolation(Exception ex)
    {
        for (Exception? t = ex; t is not null; t = t.InnerException)
        {
            if (t is SmartTokenException)
            {
                throw t;
            }
        }

        return ex;
    }

    private static SmartTokenException BodyLimitExceeded(long received, long maxBytes)
    {
        return new SmartTokenException(
            "Resposta do token endpoint excede o limite de " + maxBytes
            + " bytes (recebido/declarado: " + received + " bytes)");
    }
}
