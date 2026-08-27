// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente.Tests;

public sealed class SmartTokenExceptionTests
{
    [Fact]
    public void deveCriarExcecaoComMensagem()
    {
        var exception = new SmartTokenException("Falha de teste");

        Assert.Equal("Falha de teste", exception.Message);
        Assert.Null(exception.InnerException);
    }

    [Fact]
    public void deveCriarExcecaoComMensagemECausa()
    {
        var causa = new FormatException("JSON inválido");
        var exception = new SmartTokenException("Falha de teste", causa);

        Assert.Equal("Falha de teste", exception.Message);
        Assert.Same(causa, exception.InnerException);
    }

    [Fact]
    public void deveDerivarDeException()
    {
        var exception = new SmartTokenException("Erro");

        Assert.IsAssignableFrom<Exception>(exception);
    }
}
