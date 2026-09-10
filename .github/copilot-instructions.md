- @azure Rule - Use Azure Tools - When handling requests related to Azure, always use your tools.
- @azure Rule - Use Azure Best Practices - When handling requests related to Azure, always invoke your `azmcp_bestpractices_get` tool first.
- @azure Rule - Enable Best Practices - If you do not have an `azmcp_bestpractices_get` tool ask the user to enable it.

- HubSaúde: o contrato normativo está em `ESPECIFICACAO.md`. PKCS#11 entra via `SigningStrategyFactory.FromPkcs11` (`Pkcs11Options`). PKCS#12 no Windows usa `UserKeySet|Exportable` (não `EphemeralKeySet` para mTLS). API pública só via `SmartTokenClient.CreateBuilder()`. Testes de arquitetura em `tests/HubSaude.Cliente.Tests/ArchRules/` são bloqueantes. Mensagens de exceção em pt-BR. `ConfigureAwait(false)` em I/O da biblioteca. Homologação real: `tools/HubSaude.Smoke` com `HOMOLOG_*` (nunca credenciais no repositório). Não commitar sem pedido explícito.
