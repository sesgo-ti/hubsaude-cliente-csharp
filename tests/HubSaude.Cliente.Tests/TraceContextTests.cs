// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Text.RegularExpressions;

namespace HubSaude.Cliente.Tests;

public sealed class TraceContextTests
{
    private static readonly Regex TraceparentRegex = new(
        "^00-[0-9a-f]{32}-[0-9a-f]{16}-00$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly string AllZeroTraceId = new('0', 32);
    private static readonly string AllZeroSpanId = new('0', 16);

    [Fact]
    public void deveGerarTraceparentNoFormatoW3c()
    {
        var trace = TraceContext.Generate();

        Assert.Matches(TraceparentRegex, trace.Traceparent);
    }

    [Fact]
    public void deveGerarComponentesValidosENaoTodoZeros()
    {
        var trace = TraceContext.Generate();

        Assert.Equal(32, trace.TraceId.Length);
        Assert.Matches("^[0-9a-f]{32}$", trace.TraceId);
        Assert.NotEqual(AllZeroTraceId, trace.TraceId);

        Assert.Equal(16, trace.SpanId.Length);
        Assert.Matches("^[0-9a-f]{16}$", trace.SpanId);
        Assert.NotEqual(AllZeroSpanId, trace.SpanId);
    }

    [Fact]
    public void deveComporTraceparentComOsComponentesDaInstancia()
    {
        var trace = TraceContext.Generate();

        Assert.Equal($"00-{trace.TraceId}-{trace.SpanId}-00", trace.Traceparent);
    }

    [Fact]
    public void deveGerarValoresUnicosEntreChamadas()
    {
        const int amostras = 1000;
        var traceIds = new HashSet<string>(amostras);
        var spanIds = new HashSet<string>(amostras);

        for (var i = 0; i < amostras; i++)
        {
            var trace = TraceContext.Generate();
            traceIds.Add(trace.TraceId);
            spanIds.Add(trace.SpanId);
        }

        Assert.Equal(amostras, traceIds.Count);
        Assert.Equal(amostras, spanIds.Count);
    }

    [Fact]
    public void deveExporNomeDoHeaderTraceparent()
    {
        Assert.Equal("traceparent", TraceContext.TraceparentHeader);
    }

    [Fact]
    public void deveRejeitarTraceIdInvalido()
    {
        var spanIdValido = TraceContext.Generate().SpanId;

        var zeros = Assert.Throws<ArgumentException>(() => new TraceContext(AllZeroTraceId, spanIdValido));
        Assert.Equal("traceId", zeros.ParamName);
        Assert.Contains("trace-id", zeros.Message, StringComparison.Ordinal);

        Assert.Throws<ArgumentException>(() => new TraceContext(new string('A', 32), spanIdValido));
        Assert.Throws<ArgumentException>(() => new TraceContext("abc123", spanIdValido));
        Assert.Throws<ArgumentNullException>(() => new TraceContext(null!, spanIdValido));
    }

    [Fact]
    public void deveRejeitarSpanIdInvalido()
    {
        var traceIdValido = TraceContext.Generate().TraceId;

        var zeros = Assert.Throws<ArgumentException>(() => new TraceContext(traceIdValido, AllZeroSpanId));
        Assert.Equal("spanId", zeros.ParamName);
        Assert.Contains("span-id", zeros.Message, StringComparison.Ordinal);

        Assert.Throws<ArgumentException>(() => new TraceContext(traceIdValido, new string('F', 16)));
        Assert.Throws<ArgumentException>(() => new TraceContext(traceIdValido, "0123"));
        Assert.Throws<ArgumentNullException>(() => new TraceContext(traceIdValido, null!));
    }
}
