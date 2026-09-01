// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Reflection;
using System.Runtime.CompilerServices;
using HubSaude.Cliente.Tests.ArchRules;

namespace HubSaude.Cliente.Tests;

/// <summary>
/// Aplica as fitness functions de <see cref="ClientArchRules"/> sobre o
/// assembly de produção, no mesmo espírito de <c>HubSaudeArchitectureTest</c>
/// do cliente Java.
/// </summary>
public sealed class HubSaudeArchitectureTests
{
    [Fact]
    public void apiPublica_DeveSerAllowlistFechada()
    {
        Assert.Empty(ClientArchRules.UnexpectedPublicTypes());
    }

    [Fact]
    public void tiposPublicos_DevemSerFechadosPorPadrao()
    {
        Assert.Empty(ClientArchRules.OpenPublicTypes());
    }

    [Fact]
    public void producao_DeveViverNumUnicoNamespace()
    {
        Assert.Empty(ClientArchRules.TypesOutsideProductionNamespace());
    }

    [Fact]
    public void internavisibleTo_DeveSerApenasOProjetoDeTestes()
    {
        Assert.Contains(
            "HubSaude.Cliente.Tests",
            ClientArchRules.ProductionAssembly
                .GetCustomAttributes<InternalsVisibleToAttribute>()
                .Select(a => a.AssemblyName));
        Assert.Empty(ClientArchRules.UnexpectedInternalsVisibleTo());
    }

    [Fact]
    public void referencias_NaoDevemIncluirFrameworksVetados()
    {
        Assert.Empty(ClientArchRules.UnexpectedAssemblyReferences());
        Assert.Empty(ClientArchRules.ForbiddenTypeReferences());
    }

    [Fact]
    public void loggers_DevemSerCamposDeInstanciaNaoPublicos()
    {
        Assert.Empty(ClientArchRules.NonPrivateLoggerFields());
    }

    [Fact]
    public void createBuilder_DeveSerAUnicaEntradaPublicaDeConstrucao()
    {
        Assert.Empty(typeof(SmartTokenClient).GetConstructors(
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance));
    }
}
