# Guia para verificação e resolução de problemas de confiança SSL/TLS

Este guia é para quem integra o **HubSaude.Cliente** (.NET 10) com o
HubSaúde.

> **Nota:** o host `hub.saude.go.gov.br` é **ilustrativo** (o mesmo dos
> exemplos do [README](../README.md)); use o endpoint informado no seu
> credenciamento.

O foco é detectar se o certificado SSL/TLS do servidor não é confiável
no ambiente (por exemplo, CA raiz ausente do trust store).

O certificado do servidor pode mudar ao longo do tempo (atualmente é
emitido pelo Let's Encrypt com root ISRG Root X1).

Em **.NET 10** em um SO atualizado, a CA pública costuma já estar no
trust store. Teste primeiro, sem desabilitar a validação.

Para o SDK, em homologação ou simulador com CA própria use
`SmartTokenClientBuilder.ServerTrustAnchor`. Em produção, confie no
trust store do runtime.

## Detecção de problemas

Tente uma conexão HTTPS simples ao host do HubSaúde. Se a falha for de
confiança no certificado, siga a seção de resolução.

### Usando OpenSSL (qualquer plataforma)

Instale via pacote do SO (ex.: `apt install openssl` no Linux, ou
Homebrew no macOS). No Windows, use o OpenSSL do Git for Windows ou
equivalente.

Cadeia e verificação:

```bash
openssl s_client -connect hub.saude.go.gov.br:443 -servername hub.saude.go.gov.br < /dev/null
```

- Durante a verificação, `verify return:1` por certificado da cadeia
  indica sucesso no callback (1 = OK).
- No **final** da saída, `Verify return code:`:
  - `0 (ok)` → cadeia válida
  - `20 (unable to get local issuer certificate)` → CA raiz não
    reconhecida
  - `21 (unable to verify the first certificate)` → intermediário
    ausente
- Confirme também `Verification: OK` e, na seção "Certificate chain",
  o issuer/root (ex.: ISRG Root X1).

Validade do certificado:

```bash
echo | openssl s_client -connect hub.saude.go.gov.br:443 -servername hub.saude.go.gov.br 2>/dev/null | openssl x509 -noout -dates
```

### Em C# (.NET 10)

Projeto console com `dotnet run`:

```csharp
using System;
using System.Net.Http;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        const string endpoint = "https://hub.saude.go.gov.br";
        using var client = new HttpClient();
        try
        {
            HttpResponseMessage response = await client.GetAsync(endpoint);
            response.EnsureSuccessStatusCode();
            Console.WriteLine("Conexão bem-sucedida! Código: " + response.StatusCode);
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine("Erro: " + e.Message);
            // "The SSL connection could not be established" / falha de
            // autenticação no inner exception → confiança na CA.
            if (e.InnerException != null)
            {
                Console.WriteLine("Detalhes: " + e.InnerException.Message);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Exceção geral: " + ex.Message);
        }
    }
}
```

Erro comum: `System.Net.Http.HttpRequestException: The SSL connection
could not be established` — inspecione a inner exception.

Com o SDK, o mesmo tipo de falha aparece ao obter o token (handshake
antes do HTTP de `application/x-www-form-urlencoded`). Não use
`HttpClientHandler.DangerousAcceptAnyServerCertificateValidator` nem
callbacks que aceitam qualquer certificado.

## Resolução de problemas

Se o erro for de confiança, a CA raiz (hoje ISRG Root X1 do Let's
Encrypt) provavelmente não está no trust store. Descubra o certificado
atual da CA e, só então, importe-o. Isso é workaround para ambientes
desatualizados; prefira atualizar o runtime e o SO.

### Descobrindo o certificado da CA raiz

```bash
echo | openssl s_client -connect hub.saude.go.gov.br:443 -servername hub.saude.go.gov.br -showcerts 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > chain.pem
```

O último bloco PEM (Issuer igual a Subject) é o root. Baixe o PEM
oficial da CA (ex.:
<https://letsencrypt.org/certs/isrgrootx1.pem>) — nunca de fonte
não auditada.

### Trust store no Windows

PowerShell como administrador (converta PEM para CER se preciso):

```powershell
openssl x509 -outform der -in root.pem -out root.cer
Import-Certificate -FilePath "root.cer" -CertStoreLocation Cert:\LocalMachine\Root
```

### Trust store no Linux / macOS

Atualize as CAs do sistema (ex.: `update-ca-certificates` no Ubuntu).
O .NET usa o trust store do SO.

### Homologação e simulador (`ServerTrustAnchor`)

Quando a CA for interna, não importe “trust-all” na aplicação:

```csharp
await using var client = SmartTokenClient.CreateBuilder()
    .TokenEndpoint("https://homolog.exemplo.local/auth/token")
    .ClientId("meu-sistema")
    .PrivateKeyPem("chave-privada.pem")
    .CertificatePem("certificado.pem")
    .ServerTrustAnchor("ca-interna.pem")
    .Build();
```

`ServerTrustAnchor` aceita caminho PEM ou `X509Certificate2`. O
certificado âncora é validado na construção (RF-14).

O homolog atual (`hub-homolog.saude.go.gov.br`) exige **TLS 1.2**.
Use `.TlsProtocol("TLSv1.2")` (o padrão do SDK é TLS 1.3). Há um
console de smoke em `tools/HubSaude.Smoke` com variáveis `HOMOLOG_*`
— veja o [README](../README.md#smoke-contra-homologação-integrador).

### mTLS no Windows (Schannel)

O Schannel recusa certificado de cliente cuja chave privada foi
importada com `EphemeralKeySet` (`0x8009030D` / "credentials supplied
are not valid"). O SDK evita isso em `ClientPkcs12` e na materialização
PEM→PKCS#12 (`UserKeySet|Exportable`). Não passe um PFX carregado com
`EphemeralKeySet` para `ClientCertificate` em produção no Windows.

## Considerações finais

- Este SDK exige **.NET 10** (`net10.0`).
- Audite o servidor com [SSL Labs](https://www.ssllabs.com/ssltest/).
- Baixe certificados só de fontes oficiais da CA.
- Se o problema persistir, use o `traceId=` das `SmartTokenException`
  com o suporte do HubSaúde.
