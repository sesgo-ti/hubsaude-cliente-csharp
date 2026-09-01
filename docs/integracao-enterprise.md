# Integração enterprise

Este guia complementa o contrato da API do `hubsaude-cliente-csharp` com
decisões de integração que pertencem à aplicação consumidora. O SDK não
depende de ASP.NET, Polly, OpenTelemetry ou um contêiner de DI
específico.

## Ownership e ciclo de vida

`SmartTokenClient` é task-safe e deve ser uma instância única por
configuração de credencial. A aplicação é proprietária da instância e
deve fechá-la durante o encerramento:

- aplicações long-lived: registre-a no DI como singleton e chame
  `Dispose`/`DisposeAsync` no shutdown;
- CLIs, jobs curtos e testes: use `await using`;
- não feche a instância após cada token, pois isso descarta conexões e
  cache compartilhados.

```csharp
builder.Services.AddSingleton(sp => SmartTokenClient.CreateBuilder()
    .TokenEndpoint(tokenEndpoint)
    .ClientId(clientId)
    .PrivateKeyPem(privateKeyPath)
    .CertificatePem(certificatePath)
    .Logger(sp.GetRequiredService<ILogger<SmartTokenClient>>())
    .Build());
```

O `Dispose` é idempotente, aguarda operações em voo, encerra o
`HttpClient` interno e invalida o cache. Chamadas de token posteriores
falham com `ObjectDisposedException`.

## Composição de resiliência

O SDK repete apenas falhas transitórias de rede, com backoff exponencial
assíncrono. Respostas HTTP, inclusive `429` e `5xx`, não são repetidas
automaticamente. Um circuit breaker externo deve envolver
`ObtainTokenAsync` na camada de orquestração, sem criar outro retry
automático sobre o SDK.

Ao configurar a política:

1. conte `HttpRequestException`, `IOException` e `SmartTokenException`
   como falhas;
2. não absorva `OperationCanceledException` — propague o cancelamento;
3. trate `429` conforme `Retry-After` e a política operacional, fora do
   retry interno;
4. limite qualquer nova tentativa após `401` a uma renovação de token:
   invalide o scope, obtenha um token novo e, se o erro persistir,
   interrompa o fluxo para diagnóstico de credencial/autorização.

## Métricas

Instrumente a fachada da aplicação, não o SDK. Para Prometheus, siga a
convenção de nomes:

| Finalidade | Nome recomendado |
|------------|------------------|
| Total de solicitações | `hubsaude_<servico>_token_request_total` |
| Duração | `hubsaude_<servico>_token_request_duration_seconds` |
| Falhas | `hubsaude_<servico>_token_error_total` |

Use labels de baixa cardinalidade, como `outcome` e uma categoria fechada
de erro. Não use `scope`, `client_id`, token, trace-id, CPF, CNS ou outro
identificador pessoal como label.

Os labels de identidade de serviço e ambiente devem ser `service` e
`env`.

## Trace e diagnóstico

O SDK envia `traceparent` W3C em cada requisição HTTP (token e
descoberta). Correlacione logs da aplicação com `traceId=` nas
`SmartTokenException`. Spans completos e métricas ficam a cargo da
orquestração. Quando o OpenTelemetry .NET instrumenta o `HttpClient`,
o agente/SDK pode substituir o header pelo contexto do span ativo.

Nunca registre `access_token`, `client_assertion`, chave privada, senha,
PIN ou o corpo bruto não sanitizado de uma resposta.

Detalhes de confiança TLS estão em [`troubleshooting.md`](troubleshooting.md).

## Referências

- [README do SDK](../README.md)
- [Contrato comportamental](../ESPECIFICACAO.md)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
