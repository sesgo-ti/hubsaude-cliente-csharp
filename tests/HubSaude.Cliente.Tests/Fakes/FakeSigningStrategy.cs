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

/// <summary>
/// Espia o <see cref="IDisposable"/> da estratégia, para o cliente fechar a sessão PKCS#11/HSM.
/// </summary>
internal sealed class DisposableSigningStrategy : ISigningStrategy, IDisposable
{
    public bool Disposed { get; private set; }

    public byte[] Sign(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        ObjectDisposedException.ThrowIf(Disposed, this);
        return [1];
    }

    public void Dispose()
    {
        Disposed = true;
    }
}
