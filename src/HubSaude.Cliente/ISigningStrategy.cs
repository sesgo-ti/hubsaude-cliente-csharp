// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente;

/// <summary>
/// Estratégia de assinatura digital que abstrai a fonte da chave privada.
/// </summary>
/// <remarks>
/// Implementações podem assinar com material em memória, PKCS#12 ou HSM
/// (PKCS#11). A operação devolve a assinatura crua, sem codificação Base64.
/// </remarks>
public interface ISigningStrategy
{
    /// <summary>
    /// Assina os dados fornecidos com o mecanismo criptográfico configurado.
    /// </summary>
    /// <param name="data">Bytes a assinar (em geral, o <c>header.payload</c> do JWT).</param>
    /// <returns>Assinatura em formato bruto (não Base64).</returns>
    /// <exception cref="ArgumentNullException"><paramref name="data"/> é nulo.</exception>
    /// <exception cref="SigningException">Falha criptográfica na assinatura.</exception>
    byte[] Sign(byte[] data);
}
