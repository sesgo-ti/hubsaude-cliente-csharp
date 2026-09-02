// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace HubSaude.Cliente;

/// <summary>
/// Contexto de trace W3C gerado localmente para uma requisição HTTP do cliente.
/// </summary>
/// <remarks>
/// <para>
/// O HubSaúde deriva o identificador de correlação de cada requisição exclusivamente
/// do header <c>traceparent</c> (contexto de trace W3C); headers como
/// <c>X-Correlation-Id</c> enviados pelo cliente são ignorados pelo gateway.
/// Este tipo gera o par trace-id/span-id por requisição — sem dependência do SDK
/// OpenTelemetry — permitindo que o integrador correlacione seus logs locais com o
/// <c>correlation-id</c> registrado pela plataforma.
/// </para>
/// <para>
/// Formato emitido (W3C Trace Context §3.2):
/// <c>00-&lt;trace-id&gt;-&lt;parent-id&gt;-&lt;trace-flags&gt;</c>, onde:
/// </para>
/// <list type="bullet">
/// <item><description><strong>version</strong>: <c>00</c>;</description></item>
/// <item><description><strong>trace-id</strong>: 16 bytes aleatórios criptograficamente
/// (32 caracteres hexadecimais minúsculos), nunca todo-zeros;</description></item>
/// <item><description><strong>parent-id</strong> (span-id): 8 bytes aleatórios
/// criptograficamente (16 caracteres hexadecimais minúsculos), nunca todo-zeros;</description></item>
/// <item><description><strong>trace-flags</strong>: <c>00</c> — flag <c>sampled</c>
/// desligada, pois esta biblioteca não grava spans.</description></item>
/// </list>
/// <para>
/// Instâncias são imutáveis e validadas na construção: componentes fora do formato W3C
/// (tamanho, maiúsculas, todo-zeros) são rejeitados com <see cref="ArgumentException"/>.
/// </para>
/// </remarks>
internal sealed partial record TraceContext
{
    /// <summary>Nome do header HTTP de contexto de trace (W3C Trace Context).</summary>
    internal const string TraceparentHeader = "traceparent";

    private const string Version = "00";
    private const string FlagsNotSampled = "00";
    private const int TraceIdByteCount = 16;
    private const int SpanIdByteCount = 8;

    /// <summary>
    /// Cria um contexto de trace validado conforme W3C Trace Context.
    /// </summary>
    /// <param name="traceId">
    /// Identificador do trace — 32 caracteres hexadecimais minúsculos, não todo-zeros.
    /// </param>
    /// <param name="spanId">
    /// Identificador do span (parent-id no header) — 16 caracteres hexadecimais
    /// minúsculos, não todo-zeros.
    /// </param>
    internal TraceContext(string traceId, string spanId)
    {
        ArgumentNullException.ThrowIfNull(traceId);
        ArgumentNullException.ThrowIfNull(spanId);

        if (!TraceIdRegex().IsMatch(traceId))
        {
            throw new ArgumentException(
                "trace-id inválido: exige 32 caracteres hexadecimais minúsculos,"
                + " não todo-zeros (W3C Trace Context §3.2.2.3)",
                nameof(traceId));
        }

        if (!SpanIdRegex().IsMatch(spanId))
        {
            throw new ArgumentException(
                "span-id inválido: exige 16 caracteres hexadecimais minúsculos,"
                + " não todo-zeros (W3C Trace Context §3.2.2.4)",
                nameof(spanId));
        }

        TraceId = traceId;
        SpanId = spanId;
    }

    internal string TraceId { get; }

    /// <summary>Identificador do span (parent-id no header <c>traceparent</c>).</summary>
    internal string SpanId { get; }

    /// <summary>
    /// Valor do header <c>traceparent</c> no formato
    /// <c>00-&lt;trace-id&gt;-&lt;parent-id&gt;-00</c> (W3C Trace Context §3.2.2).
    /// </summary>
    internal string Traceparent => $"{Version}-{TraceId}-{SpanId}-{FlagsNotSampled}";

    /// <summary>
    /// Gera um novo contexto de trace com trace-id e span-id aleatórios criptograficamente.
    /// </summary>
    /// <remarks>
    /// Deve ser invocado uma vez por requisição HTTP: cada tentativa (inclusive retries)
    /// carrega um par trace-id/span-id próprio.
    /// </remarks>
    /// <returns>Novo contexto de trace, nunca todo-zeros.</returns>
    internal static TraceContext Generate()
    {
        return new TraceContext(RandomLowerHex(TraceIdByteCount), RandomLowerHex(SpanIdByteCount));
    }

    private static string RandomLowerHex(int byteCount)
    {
        Span<byte> bytes = stackalloc byte[byteCount];
        do
        {
            RandomNumberGenerator.Fill(bytes);
        }
        while (AllZeros(bytes));

        return Convert.ToHexStringLower(bytes);
    }

    private static bool AllZeros(ReadOnlySpan<byte> bytes)
    {
        return bytes.IndexOfAnyExcept((byte)0) < 0;
    }

    [GeneratedRegex("^(?!0{32}$)[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex TraceIdRegex();

    [GeneratedRegex("^(?!0{16}$)[0-9a-f]{16}$", RegexOptions.CultureInvariant)]
    private static partial Regex SpanIdRegex();
}
