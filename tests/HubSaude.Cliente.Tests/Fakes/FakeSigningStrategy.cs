// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente.Tests.Fakes;

/// <summary>
/// Estratégia de teste: devolve uma assinatura vazia sem criptografia.
/// </summary>
internal sealed class FakeSigningStrategy : ISigningStrategy
{
    public byte[] Sign(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return [];
    }
}
