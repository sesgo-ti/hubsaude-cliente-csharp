// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Text.Json;

namespace HubSaude.Cliente;

/// <summary>
/// Descoberta do <c>token_endpoint</c> via <c>/.well-known/smart-configuration</c>
/// (SMART on FHIR) e validação de URLs quanto ao uso obrigatório de https.
/// </summary>
/// <remarks>
/// <para>
/// Colaborador interno do <see cref="SmartTokenClientBuilder"/>, extraído para reduzir a
/// complexidade do builder. Não faz parte da API pública: consumidores usam
/// <see cref="SmartTokenClientBuilder.DiscoverTokenEndpointAsync"/>.
/// </para>
/// </remarks>
internal static class SmartConfigurationDiscovery
{
    /// <summary>
    /// Descobre o <c>token_endpoint</c> consultando o <c>/.well-known/smart-configuration</c>
    /// a partir de uma URL base FHIR.
    /// </summary>
    /// <remarks>
    /// <para>
    /// O valor retornado pelo servidor é validado: deve usar o esquema <c>https</c>
    /// (exceção para <c>localhost</c>/<c>127.0.0.1</c>), evitando que um endpoint inseguro
    /// seja adotado silenciosamente.
    /// </para>
    /// <para>
    /// A requisição carrega um header <c>traceparent</c> (W3C Trace Context) gerado
    /// localmente; em caso de falha, o trace-id integra a mensagem de erro para correlação
    /// com a plataforma.
    /// </para>
    /// </remarks>
    /// <param name="fhirBaseUrl">URL base do servidor FHIR.</param>
    /// <param name="handler">Handler HTTP com configuração TLS/mTLS.</param>
    /// <param name="requestTimeout">Timeout da requisição HTTP.</param>
    /// <param name="disposeHandler">Se o handler deve ser descartado após o uso.</param>
    /// <param name="cancellationToken">Token de cancelamento.</param>
    /// <returns>A URL do <c>token_endpoint</c> resolvida dinamicamente.</returns>
    /// <exception cref="SmartTokenException">
    /// Em caso de falha HTTP, JSON inválido ou <c>token_endpoint</c> ausente/inválido.
    /// </exception>
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

    /// <summary>
    /// Exige esquema <c>https</c> para URLs de produção; permite <c>http</c> apenas em localhost.
    /// </summary>
    /// <param name="url">URL a validar.</param>
    /// <param name="campo">Nome do campo na mensagem de erro (ex.: <c>token_endpoint</c>).</param>
    /// <exception cref="ArgumentException">Quando a URL é inválida ou não usa https fora de localhost.</exception>
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
