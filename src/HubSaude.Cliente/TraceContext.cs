// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace HubSaude.Cliente;

/// <summary>
/// Contexto de trace W3C gerado localmente para uma requisição HTTP (RF-02.4).
/// </summary>
internal sealed partial record TraceContext
{
    internal const string TraceparentHeader = "traceparent";

    private const string Version = "00";
    private const string FlagsNotSampled = "00";
    private const int TraceIdByteCount = 16;
    private const int SpanIdByteCount = 8;

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

    internal string SpanId { get; }

    internal string Traceparent => $"{Version}-{TraceId}-{SpanId}-{FlagsNotSampled}";

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
