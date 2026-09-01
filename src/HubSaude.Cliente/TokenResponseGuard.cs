// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace HubSaude.Cliente;

/// <summary>
/// Sanidade de <c>expires_in</c> e teto de tamanho do corpo HTTP.
/// </summary>
internal static class TokenResponseGuard
{
    internal const int DefaultExpiresInSeconds = 3600;
    internal const int MaxExpiresInSeconds = 86_400;
    internal const long MaxResponseBodyBytes = 1_048_576L;

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
