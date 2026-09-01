# Como contribuir com hubsaude-cliente-csharp

Obrigado pelo interesse em contribuir! Este documento descreve o processo
padronizado de contribuição.

## Código de conduta

Toda interação está sujeita ao [Código de Conduta](CODE_OF_CONDUCT.md),
baseado no Contributor Covenant 2.1.

## Licença das contribuições

Ao submeter um Pull Request, você concorda em licenciar sua contribuição
sob a **Apache License 2.0**, a mesma licença deste projeto. Veja
[LICENSE](LICENSE).

## Developer Certificate of Origin (DCO)

Este projeto adota o [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Toda contribuição precisa ter `Signed-off-by:` em cada commit.

Assine automaticamente:

```bash
git commit -s -m "feat: minha alteração"
```

Isso adiciona ao corpo da mensagem:

```text
Signed-off-by: Seu Nome <seu@email.com>
```

Esse trailer atesta que você tem direito de submeter o trabalho sob a
licença do projeto, conforme o texto integral do DCO. O workflow
[`.github/workflows/dco.yml`](.github/workflows/dco.yml) falha o check
do Pull Request se algum commit (exceto Dependabot / `github-actions`)
não tiver `Signed-off-by:`. Para impedir o merge mesmo com o check
vermelho, o check DCO precisa ser obrigatório no ruleset da branch
`develop` (ainda não está).

## Fluxo de contribuição

1. **Issue primeiro**: abra ou comente em uma issue descrevendo o problema
   ou a feature.

2. **Fork e branch**: trabalhe em branch dedicado a partir de `develop`.
   Nome sugerido: `feat/curto-descritivo`, `fix/issue-123`, `docs/...`.

3. **Conventional Commits**:

   * `feat:` nova funcionalidade
   * `fix:` correção de bug
   * `docs:` documentação
   * `refactor:`, `test:`, `chore:`, `perf:`, `build:`, `ci:`

4. **Testes obrigatórios**: toda mudança de comportamento exige teste novo
   ou atualização do existente. Cobertura é monitorada via Coverlet
   (mínimo de 85% no `hubsaude-cliente-csharp`).

5. **Build verde** localmente antes de abrir PR:

   ```bash
   dotnet test HubSaude.Cliente.sln --configuration Release
   ```

   O gate de cobertura já está configurado no projeto de testes; falhas abaixo
   de 85% de line coverage interrompem o build.

6. **PR pequeno e focado**: prefira PRs de até ~400 linhas modificadas.

7. **Descrição do PR**: explique *o quê*, *por quê* e *como testar*.
   Referencie issues com `Closes #123`.

## Padrões técnicos

* .NET: utilizar a versão do SDK especificada em `global.json`, quando presente.
* C#: seguir as convenções oficiais de nomenclatura e estilo da linguagem.
* Linhas: preferencialmente curtas e legíveis; respeitar as regras de formatação
  configuradas no projeto (`.editorconfig`).
* XML documentation comments: a API pública deve ser documentada com comentários
  XML quando aplicável.
* Nullable Reference Types: manter o tratamento de nulabilidade habilitado e
  corrigir warnings relacionados a referências nulas.
* Async/await: operações de I/O assíncronas devem utilizar async/await conforme
  as convenções do .NET.
* IDisposable: recursos que exigem liberação explícita devem seguir o padrão
  `IDisposable`/`IAsyncDisposable` apropriado.
* Testes: testes automatizados devem ser independentes de serviços externos
  sempre que possível. Cobertura Coverlet: mínimo de 85% de linha em Release.
* **Sem `Console.WriteLine` no assembly de produção**: use `ILogger`
  (`Microsoft.Extensions.Logging.Abstractions`).
* **Testes de arquitetura** (`ClientArchRules` em
  `tests/HubSaude.Cliente.Tests/ArchRules/`, aplicados por
  `HubSaudeArchitectureTests`): API pública em allowlist, tipos públicos
  fechados (`sealed`/`static`/`interface`/`record`), namespace único
  `HubSaude.Cliente`, `InternalsVisibleTo` só para testes, sem referências
  a ASP.NET/EF/Newtonsoft/Kafka e sem `System.Console`. Equivalente
  idiomático às regras ArchUnit do cliente Java (não há pacote
  `domain` neste SDK).
* `ILogger` de produção deve ser campo de instância não público (não
  `static`/`public`); o idioma Java `private static final Logger` não se
  aplica ao `ILogger` do .NET.
* Dependências: evitar dependências desnecessárias e manter os pacotes NuGet
  atualizados conforme a política do projeto. Terceiros permitidos na
  biblioteca: BouncyCastle (PEM) e logging abstractions.

## Política de versionamento

[Semantic Versioning 2.0.0](https://semver.org/lang/pt-BR/):

* durante a série `0.x`, **MINOR** pode incluir mudanças incompatíveis e
  **PATCH** preserva compatibilidade;
* a partir de `1.0.0`, **MAJOR** indica quebra na API pública, **MINOR**
  adiciona funcionalidade compatível e **PATCH** contém correções compatíveis.

Apenas a MAJOR mais recente recebe correções de segurança
(ver [SECURITY.md](SECURITY.md)).

## Política de segurança

Vulnerabilidades **não** devem ser reportadas como issues públicas. Veja
[SECURITY.md](SECURITY.md) para o canal apropriado.

## Dúvidas

Abra uma [Discussion](https://github.com/sesgo-ti/hubsaude-cliente-csharp/discussions)
ou contate os mantenedores via issue.
