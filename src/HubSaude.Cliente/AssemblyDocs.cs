// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente;

/// <summary>
/// Biblioteca cliente .NET do HubSaúde para obtenção de access tokens SMART Backend
/// Services (<c>client_credentials</c> + <c>private_key_jwt</c>, RFC 7523).
/// </summary>
/// <remarks>
/// <para>
/// O ponto de entrada é <see cref="SmartTokenClient"/> (construído por
/// <see cref="SmartTokenClientBuilder"/>), que assina o <c>client_assertion</c>
/// com o material criptográfico do estabelecimento e negocia o token no
/// authorization server. O pacote reúne os colaboradores dessa jornada:
/// estratégias de assinatura (<see cref="ISigningStrategy"/> e
/// <see cref="SigningStrategyFactory"/>), carga e validação de material PEM
/// (<see cref="PemLoader"/>), tolerância a falhas com retry exponencial
/// (<see cref="FaultToleranceConfig"/>, <see cref="RetryPolicy"/>), salvaguardas
/// de sanidade da resposta do token endpoint e propagação de contexto de trace
/// W3C.
/// </para>
/// <para>
/// A biblioteca é distribuída para consumidores externos; seu contrato público
/// segue compatibilidade forward na série <c>0.x</c> e as exceções de domínio
/// (<see cref="SmartTokenException"/>, <see cref="SigningException"/>) não
/// expõem detalhes de credenciais.
/// </para>
/// </remarks>
internal static class AssemblyDocs
{
}
