// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente;

/// <summary>
/// Falha de domínio nas operações do <see cref="SmartTokenClient"/>.
/// </summary>
/// <remarks>
/// Sinaliza configuração inválida de material criptográfico, respostas
/// inesperadas do servidor de autorização ou JSON inválido, preservando a
/// causa original para diagnóstico. Mensagens não expõem segredos.
/// </remarks>
public sealed class SmartTokenException : Exception
{
    /// <summary>
    /// Cria a exceção com mensagem descritiva.
    /// </summary>
    /// <param name="message">Descrição da falha em pt-BR.</param>
    public SmartTokenException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Cria a exceção preservando a causa original.
    /// </summary>
    /// <param name="message">Descrição da falha em pt-BR.</param>
    /// <param name="innerException">Causa original; nulo quando não houver.</param>
    public SmartTokenException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}
