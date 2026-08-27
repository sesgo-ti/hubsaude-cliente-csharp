# Como contribuir com hubsaude-cliente-csharp

Obrigado pelo interesse em contribuir! Este documento descreve o processo
padronizado de contribui??o.

## C?digo de conduta

Toda intera??o est? sujeita ao [C?digo de Conduta](CODE_OF_CONDUCT.md),
baseado no Contributor Covenant 2.1.

## Licen?a das contribui??es

Ao submeter um Pull Request, voc? concorda em licenciar sua contribui??o
sob a **Apache License 2.0**, a mesma licen?a deste projeto. Veja
[LICENSE](LICENSE).

## Developer Certificate of Origin (DCO)

Este projeto adota o [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Toda contribui??o precisa ter `Signed-off-by:` em cada commit.

Assine automaticamente:

```bash
git commit -s -m "feat: minha altera??o"
```

Isso adiciona ao corpo da mensagem:

```text
Signed-off-by: Seu Nome <seu@email.com>
```

Esse trailer atesta que voc? tem direito de submeter o trabalho sob a
licen?a do projeto, conforme o texto integral do DCO. Commits sem
`Signed-off-by:` ser?o bloqueados pelo CI.

## Fluxo de contribui??o

1. **Issue primeiro**: abra ou comente em uma issue descrevendo o problema
   ou a feature.

2. **Fork e branch**: trabalhe em branch dedicado a partir de `develop`.
   Nome sugerido: `feat/curto-descritivo`, `fix/issue-123`, `docs/...`.

3. **Conventional Commits**:

   * `feat:` nova funcionalidade
   * `fix:` corre??o de bug
   * `docs:` documenta??o
   * `refactor:`, `test:`, `chore:`, `perf:`, `build:`, `ci:`

4. **Testes obrigat?rios**: toda mudan?a de comportamento exige teste novo
   ou atualiza??o do existente. Cobertura ? monitorada via Coverlet
   (m?nimo de 85% no `hubsaude-cliente-csharp`).

5. **Build verde** localmente antes de abrir PR:

   ```bash
   dotnet test HubSaude.Cliente.sln --configuration Release
   ```

   O gate de cobertura j? est? configurado no projeto de testes; falhas abaixo
   de 85% de line coverage interrompem o build.

6. **PR pequeno e focado**: prefira PRs de at? ~400 linhas modificadas.

7. **Descri??o do PR**: explique *o qu?*, *por qu?* e *como testar*.
   Referencie issues com `Closes #123`.

## Padr?es t?cnicos

* .NET: utilizar a vers?o do SDK especificada em `global.json`, quando presente.
* C#: seguir as conven??es oficiais de nomenclatura e estilo da linguagem.
* Linhas: preferencialmente curtas e leg?veis; respeitar as regras de formata??o
  configuradas no projeto (`.editorconfig`).
* XML documentation comments: a API p?blica deve ser documentada com coment?rios
  XML quando aplic?vel.
* Nullable Reference Types: manter o tratamento de nulabilidade habilitado e
  corrigir warnings relacionados a refer?ncias nulas.
* Async/await: opera??es de I/O ass?ncronas devem utilizar async/await conforme
  as conven??es do .NET.
* IDisposable: recursos que exigem libera??o expl?cita devem seguir o padr?o
  `IDisposable`/`IAsyncDisposable` apropriado.
* Testes: testes automatizados devem ser independentes de servi?os externos
  sempre que poss?vel.
* Depend?ncias: evitar depend?ncias desnecess?rias e manter os pacotes NuGet
  atualizados conforme a pol?tica do projeto.

## Pol?tica de versionamento

[Semantic Versioning 2.0.0](https://semver.org/lang/pt-BR/):

* durante a s?rie `0.x`, **MINOR** pode incluir mudan?as incompat?veis e
  **PATCH** preserva compatibilidade;
* a partir de `1.0.0`, **MAJOR** indica quebra na API p?blica, **MINOR**
  adiciona funcionalidade compat?vel e **PATCH** cont?m corre??es compat?veis.

Apenas a MAJOR mais recente recebe corre??es de seguran?a
(ver [SECURITY.md](SECURITY.md)).

## Pol?tica de seguran?a

Vulnerabilidades **n?o** devem ser reportadas como issues p?blicas. Veja
[SECURITY.md](SECURITY.md) para o canal apropriado.

## D?vidas

Abra uma [Discussion](https://github.com/sesgo-ti/hubsaude-cliente-csharp/discussions)
ou contate os mantenedores via issue.
