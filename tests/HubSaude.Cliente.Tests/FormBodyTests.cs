// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente.Tests;

public sealed class FormBodyTests
{
    [Fact]
    public void deveIncluirParametrosObrigatoriosPercentEncoded()
    {
        var body = SmartTokenClient.BuildFormBody(
            "test-client",
            "eyJhbGciOiJSUzM4NCJ9.e30.sig",
            "system/Patient.rs");

        Assert.Contains("grant_type=client_credentials", body, StringComparison.Ordinal);
        Assert.Contains("client_id=test-client", body, StringComparison.Ordinal);
        Assert.Contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
            body,
            StringComparison.Ordinal);
        Assert.Contains("&client_assertion=eyJhbGciOiJSUzM4NCJ9.e30.sig", body, StringComparison.Ordinal);
        Assert.Contains("&scope=system%2FPatient.rs", body, StringComparison.Ordinal);
    }

    [Fact]
    public void deveOmitirScopeQuandoNuloVazioOuEmBranco()
    {
        Assert.DoesNotContain("scope=", SmartTokenClient.BuildFormBody("id", "jwt", null), StringComparison.Ordinal);
        Assert.DoesNotContain("scope=", SmartTokenClient.BuildFormBody("id", "jwt", string.Empty), StringComparison.Ordinal);
        Assert.DoesNotContain("scope=", SmartTokenClient.BuildFormBody("id", "jwt", "   "), StringComparison.Ordinal);
    }

    [Fact]
    public void devePercentEncodeEspacosComoMais()
    {
        Assert.Equal("a+b", SmartTokenClient.Encode("a b"));
        var body = SmartTokenClient.BuildFormBody("id com espaco", "jwt", "system/Patient.rs system/Observation.rs");
        Assert.Contains("client_id=id+com+espaco", body, StringComparison.Ordinal);
        Assert.Contains("scope=system%2FPatient.rs+system%2FObservation.rs", body, StringComparison.Ordinal);
    }

    [Fact]
    public void encode_DeveRejeitarNulo()
    {
        Assert.Throws<ArgumentNullException>(() => SmartTokenClient.Encode(null!));
    }

    [Fact]
    public void buildFormBody_DeveRejeitarArgumentosNulos()
    {
        Assert.Throws<ArgumentNullException>(() => SmartTokenClient.BuildFormBody(null!, "jwt", null));
        Assert.Throws<ArgumentNullException>(() => SmartTokenClient.BuildFormBody("id", null!, null));
    }
}
