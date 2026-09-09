# Ruleset da branch `develop`

Espelha a política do [`hubsaude-cliente-java`](https://github.com/sesgo-ti/hubsaude-cliente-java):
contribuições com **`git commit -s`** (DCO), **sem** exigir assinatura
GPG/SSH.

Este JSON documenta a configuração aplicada no GitHub. Para sincronizar
após editar:

```bash
gh api repos/sesgo-ti/hubsaude-cliente-csharp/rulesets/22046384 \
  --method PUT --input .github/rulesets/develop.json
```

Checks obrigatórios antes do merge:

| Contexto | Origem |
|----------|--------|
| `signed-off-by` | [`.github/workflows/dco.yml`](../workflows/dco.yml) |
| `verify` | [`.github/workflows/ci.yml`](../workflows/ci.yml) |

Cobertura mínima de 85% continua no gate do Coverlet em `dotnet test`
(CI), não no ruleset.
