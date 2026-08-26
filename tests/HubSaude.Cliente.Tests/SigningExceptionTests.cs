// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente.Tests;

public sealed class SigningExceptionTests
{
    [Fact]
    public void deveCriarExcecaoComMensagem()
    {
        var exception = new SigningException("Erro de teste");

        Assert.Equal("Erro de teste", exception.Message);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void deveCriarExcecaoComMensagemECausa()
    {
        var causa = new InvalidOperationException("causa original");
        var exception = new SigningException("Erro de teste", causa);

        Assert.Equal("Erro de teste", exception.Message);
        Assert.Same(causa, exception.InnerException);
    }

    [Fact]
    public void deveDerivarDeException()
    {
        var exception = new SigningException("Erro");

        Assert.IsAssignableFrom<Exception>(exception);
    }
}
