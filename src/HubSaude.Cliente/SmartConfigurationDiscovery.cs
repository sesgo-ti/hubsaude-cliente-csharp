// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Text.Json;

namespace HubSaude.Cliente;

/// <summary>
/// Descoberta de <c>token_endpoint</c> via <c>/.well-known/smart-configuration</c> (RF-09).
/// </summary>
internal static class SmartConfigurationDiscovery
{
    internal static async Task<string> DiscoverTokenEndpointAsync(
        string fhirBaseUrl,
        HttpMessageHandler handler,
        TimeSpan requestTimeout,
        bool disposeHandler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fhirBaseUrl);
        ArgumentNullException.ThrowIfNull(handler);

        var wellKnownUrl = fhirBaseUrl.EndsWith('/')
            ? fhirBaseUrl + ".well-known/smart-configuration"
            : fhirBaseUrl + "/.well-known/smart-configuration";

        var trace = TraceContext.Generate();
        using var client = new HttpClient(handler, disposeHandler) { Timeout = requestTimeout };
        using var request = new HttpRequestMessage(HttpMethod.Get, wellKnownUrl);
        request.Headers.TryAddWithoutValidation(TraceContext.TraceparentHeader, trace.Traceparent);

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new HttpRequestException("Requisi\u00e7\u00e3o para smart-configuration expirou", ex);
        }
        catch (OperationCanceledException)
        {
            throw;
        }

        using (response)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if ((int)response.StatusCode != 200)
            {
                throw new SmartTokenException(
                    "Falha ao obter smart-configuration (" + (int)response.StatusCode
                    + ", traceId=" + trace.TraceId + "): "
                    + ErrorClassifier.SanitizeErrorResponse(body));
            }

            JsonDocument document;
            try
            {
                document = JsonDocument.Parse(body);
            }
            catch (JsonException ex)
            {
                throw new SmartTokenException("A resposta de smart-configuration n\u00e3o \u00e9 JSON v\u00e1lido", ex);
            }

            using (document)
            {
                if (!document.RootElement.TryGetProperty("token_endpoint", out var endpointNode)
                    || endpointNode.ValueKind != JsonValueKind.String
                    || string.IsNullOrWhiteSpace(endpointNode.GetString()))
                {
                    throw new SmartTokenException(
                        "A resposta de smart-configuration n\u00e3o cont\u00e9m 'token_endpoint'");
                }

                var discovered = endpointNode.GetString()!;
                RequireHttps(discovered, "token_endpoint descoberto");
                return discovered;
            }
        }
    }

    internal static void RequireHttps(string url, string campo)
    {
        ArgumentNullException.ThrowIfNull(url);
        ArgumentNullException.ThrowIfNull(campo);

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException(
                campo + " inv\u00e1lido: '" + url + "' n\u00e3o \u00e9 uma URL v\u00e1lida",
                nameof(url));
        }

        if (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var host = uri.Host;
        var hostLocal = host is not null
            && (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
                || host == "127.0.0.1"
                || host == "[::1]"
                || host == "::1");
        if (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && hostLocal)
        {
            return;
        }

        throw new ArgumentException(
            campo + " deve usar o esquema https (recebido: '" + url + "')."
            + " O esquema http \u00e9 permitido apenas para localhost/127.0.0.1,"
            + " em desenvolvimento e testes locais.");
    }
}
