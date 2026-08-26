// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente;

/// <summary>
/// Falha durante a operação de assinatura digital da <see cref="ISigningStrategy"/>.
/// </summary>
public sealed class SigningException : Exception
{
    /// <summary>
    /// Cria a exceção com mensagem descritiva.
    /// </summary>
    /// <param name="message">Descrição do erro em pt-BR.</param>
    public SigningException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Cria a exceção preservando a causa original.
    /// </summary>
    /// <param name="message">Descrição do erro em pt-BR.</param>
    /// <param name="innerException">Causa original; nulo quando não houver.</param>
    public SigningException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
