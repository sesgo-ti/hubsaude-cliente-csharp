// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente.Tests;

public sealed class AssemblySmokeTests
{
    [Fact]
    public void BibliotecaReferenciada_DeveCarregar()
    {
        var assembly = typeof(HubSaude.Cliente.AssemblyMarker).Assembly;
        Assert.Equal("HubSaude.Cliente", assembly.GetName().Name);
    }
}
