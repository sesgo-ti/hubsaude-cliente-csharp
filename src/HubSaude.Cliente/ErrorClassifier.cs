// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace HubSaude.Cliente;

/// <summary>
/// Classifica falhas na obtenção de token: retry, heurística mTLS e erros HTTP (RF-03, RF-07, RF-08, RNF-02).
/// </summary>
internal sealed partial class ErrorClassifier
{
    internal const int HttpTooManyRequests = 429;
    private const int MaxErrorResponseLength = 500;

    private readonly string _clientId;
    private readonly string _tokenEndpoint;
    private readonly ILogger _logger;

    internal ErrorClassifier(string clientId, string tokenEndpoint, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(tokenEndpoint);
        ArgumentNullException.ThrowIfNull(logger);
        _clientId = clientId;
        _tokenEndpoint = tokenEndpoint;
        _logger = logger;
    }

    internal Exception RetriableOrRethrow(Exception ex, TraceContext trace)
    {
        if (IsLikelyClientCertificateRejection(ex))
        {
            _logger.LogError(
                "Falha de TLS ap\u00f3s handshake mTLS para clientId={ClientId} endpoint={Endpoint} traceId={TraceId}: {Error}."
                + " Causa prov\u00e1vel: certificado de cliente rejeitado pelo servidor"
                + " (revogado, expirado ou n\u00e3o confi\u00e1vel) \u2014 o servidor abortou a conex\u00e3o"
                + " em vez de retornar uma resposta HTTP de erro.",
                _clientId,
                _tokenEndpoint,
                trace.TraceId,
                ex.ToString());
            throw new SmartTokenException(
                "Conex\u00e3o TLS abortada pelo servidor ap\u00f3s o handshake mTLS contra "
                + _tokenEndpoint
                + ". Causa prov\u00e1vel: certificado de cliente rejeitado"
                + " (revogado, expirado ou n\u00e3o confi\u00e1vel)."
                + " Verifique a validade do certificado em uso e, se ele estiver"
                + " correto, contate o operador do servidor de autoriza\u00e7\u00e3o \u2014"
                + " a resposta esperada nesse cen\u00e1rio seria um alerta TLS"
                + " (certificate_revoked/certificate_expired) ou HTTP 401,"
                + " e n\u00e3o o encerramento abrupto da conex\u00e3o.",
                ex);
        }

        if (IsTransientNetworkFailure(ex))
        {
            return ex;
        }

        throw ex;
    }

    internal static bool IsTransientNetworkFailure(Exception ex)
    {
        for (Exception? t = ex; t is not null; t = t.InnerException)
        {
            if (IsSslFailure(t))
            {
                return false;
            }

            if (t is TimeoutException
                or EndOfStreamException
                or SocketException
                or HttpIOException)
            {
                return true;
            }

            if (t is TaskCanceledException)
            {
                return true;
            }

            if (t is HttpRequestException http
                && (http.HttpRequestError is HttpRequestError.ConnectionError
                    or HttpRequestError.NameResolutionError
                    or HttpRequestError.ResponseEnded))
            {
                return true;
            }

            var msg = t.Message;
            if (msg is not null && msg.Contains("received no bytes", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    internal static bool IsLikelyClientCertificateRejection(Exception? ex)
    {
        for (Exception? t = ex; t is not null; t = t.InnerException)
        {
            if (IsServerCertificateValidationFailure(t))
            {
                return false;
            }
        }

        for (Exception? t = ex; t is not null; t = t.InnerException)
        {
            if (t is AuthenticationTagMismatchException || t is AuthenticationException)
            {
                return true;
            }

            var msg = t.Message;
            if (msg is not null && msg.Contains("bad_record_mac", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    internal SmartTokenException HttpFailure(
        HttpStatusCode statusCode,
        string? retryAfter,
        string? body,
        TraceContext trace)
    {
        var status = (int)statusCode;
        if (status == HttpTooManyRequests)
        {
            _logger.LogWarning(
                "Rate limit (HTTP 429) para clientId={ClientId} traceId={TraceId} \u2014 sem retry autom\u00e1tico",
                _clientId,
                trace.TraceId);
        }
        else
        {
            _logger.LogError(
                "Falha ao obter token: HTTP {Status} para clientId={ClientId} traceId={TraceId}",
                status,
                _clientId,
                trace.TraceId);
        }

        var retryAfterPart = string.IsNullOrWhiteSpace(retryAfter)
            ? string.Empty
            : " (Retry-After: " + retryAfter.Trim() + ")";
        var hint = status == HttpTooManyRequests
            ? " Rate limit atingido; a decis\u00e3o de aguardar e reenviar \u00e9 do chamador."
            : string.Empty;
        return new SmartTokenException(
            "Falha ao obter token: HTTP " + status + retryAfterPart
            + " (traceId=" + trace.TraceId + ")"
            + " \u2014 " + SanitizeErrorResponse(body) + hint);
    }

    internal static string SanitizeErrorResponse(string? responseBody)
    {
        if (responseBody is null)
        {
            return "<empty>";
        }

        var redacted = JsonTokenRegex().Replace(responseBody, "$1:\"[REDACTED]\"");
        redacted = FormTokenRegex().Replace(redacted, "$1=[REDACTED]");
        if (redacted.Length > MaxErrorResponseLength)
        {
            return redacted[..MaxErrorResponseLength] + "...";
        }

        return redacted;
    }

    private static bool IsSslFailure(Exception t)
    {
        if (t is AuthenticationException)
        {
            return true;
        }

        if (t is HttpRequestException http && http.HttpRequestError == HttpRequestError.SecureConnectionError)
        {
            return true;
        }

        var typeName = t.GetType().FullName ?? string.Empty;
        return typeName.Contains("Ssl", StringComparison.Ordinal)
            || typeName.Contains("AuthenticationException", StringComparison.Ordinal);
    }

    private static bool IsServerCertificateValidationFailure(Exception t)
    {
        if (t is CryptographicException and not AuthenticationTagMismatchException)
        {
            var msg = t.Message ?? string.Empty;
            if (msg.Contains("PKIX", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("certification path", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("X509", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("certificate", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (t is AuthenticationException)
        {
            var msg = t.Message ?? string.Empty;
            if (msg.Contains("RemoteCertificate", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("PKIX", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("certificate chain", StringComparison.OrdinalIgnoreCase)
                || msg.Contains("The remote certificate", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        var typeName = t.GetType().FullName ?? string.Empty;
        if (typeName.Contains("CertificateException", StringComparison.Ordinal)
            || typeName.Contains("CertPath", StringComparison.Ordinal)
            || typeName.Contains(nameof(X509Certificate), StringComparison.Ordinal))
        {
            return t is not AuthenticationTagMismatchException;
        }

        var message = t.Message ?? string.Empty;
        return message.Contains("PKIX", StringComparison.OrdinalIgnoreCase)
            || message.Contains("certification path", StringComparison.OrdinalIgnoreCase);
    }

    [GeneratedRegex("(\"(?:access_token|token)\")\\s*:\\s*\"[^\"]*\"", RegexOptions.CultureInvariant)]
    private static partial Regex JsonTokenRegex();

    [GeneratedRegex("(access_token|token)=[^&\\s]*", RegexOptions.CultureInvariant)]
    private static partial Regex FormTokenRegex();
}
