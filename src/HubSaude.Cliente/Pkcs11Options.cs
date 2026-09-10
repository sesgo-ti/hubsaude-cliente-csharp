// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente;

/// <summary>
/// Opções de acesso a um HSM/token PKCS#11 para
/// <see cref="SigningStrategyFactory.FromPkcs11"/>.
/// </summary>
public sealed class Pkcs11Options
{
    /// <summary>
    /// Caminho do módulo PKCS#11 do fabricante (<c>.so</c>, <c>.dll</c> ou <c>.dylib</c>).
    /// </summary>
    public required string Library { get; init; }

    /// <summary>PIN de usuário do token (<c>CKU_USER</c>).</summary>
    public required string Pin { get; init; }

    /// <summary>
    /// <c>CKA_LABEL</c> da chave privada. Ao menos um entre <see cref="KeyLabel"/>
    /// e <see cref="KeyId"/> é obrigatório.
    /// </summary>
    public string? KeyLabel { get; init; }

    /// <summary>
    /// <c>CKA_ID</c> da chave privada. Muitos tokens pareiam chave e certificado por este id.
    /// </summary>
    public byte[]? KeyId { get; init; }

    /// <summary>
    /// Índice na lista de slots com token presente. Mutuamente exclusivo com
    /// <see cref="TokenLabel"/>.
    /// </summary>
    public int? Slot { get; init; }

    /// <summary>
    /// Label do token (<c>CKA_LABEL</c> do token). Mutuamente exclusivo com
    /// <see cref="Slot"/>.
    /// </summary>
    public string? TokenLabel { get; init; }

    /// <summary>Algoritmo JWT a usar na assinatura (padrão <c>RS384</c>).</summary>
    public string JwtAlgorithm { get; init; } = SmartTokenClient.DefaultJwtAlgorithm;
}
