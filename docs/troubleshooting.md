# Guia para Verificação e Resolução de Problemas de Confiança em Certificados SSL/TLS

Este guia é direcionado ao desenvolvedor que está integrando um sistema
com o HubSaúde, em https://hub.saude.go.gov.br. 

> **Nota:** o host `hub.saude.go.gov.br` é **ilustrativo** (o mesmo dos
> exemplos do [README](../README.md)); use o endpoint informado no seu
> credenciamento.

O foco é ajudar a detectar se há problemas de confiança no certificado 
SSL/TLS do servidor (por exemplo, se o root CA não for reconhecido 
pelo seu ambiente). 

O certificado do servidor pode mudar ao longo do tempo (atualmente, 
é emitido pelo Let's Encrypt com root ISRG Root X1). 
Vamos cobrir detecção em Java, C# (.NET), JavaScript (Node.js) e 
OpenSSL, além de passos para resolver importando o certificado da 
CA raiz se necessário.

**Importante:** Em ambientes modernos (Java 11+, .NET 6+, Node.js recente), 
o certificado deve ser confiável automaticamente. Teste primeiro!

## Detecção de problemas

Aqui, mostramos como tentar uma conexão HTTPS simples ao endpoint https://hub.saude.go.gov.br e capturar erros relacionados a certificados (ex.: "PKIX path building failed" ou "SSL handshake failed"). Se a conexão falhar com erro de confiança, prossiga para a seção de resolução.

### Usando OpenSSL (Linha de Comando - Qualquer Plataforma)
OpenSSL é uma ferramenta gratuita e essencial para troubleshooting. Instale via pacote do seu SO (ex.: `apt install openssl` no Linux, ou via Homebrew no macOS).

Comando para testar a conexão e verificar a cadeia:
```
openssl s_client -connect hub.saude.go.gov.br:443 -servername hub.saude.go.gov.br < /dev/null
```

- **O que observar:**
    - Durante a verificação, você verá linhas como `verify return:1` para cada certificado na cadeia — isso é **normal e indica sucesso** (1 = callback retornou OK).
    - No **final da saída**, procure por `Verify return code:`:
        - `Verify return code: 0 (ok)` → cadeia válida, certificado confiável ✓
        - `Verify return code: 20 (unable to get local issuer certificate)` → CA raiz não reconhecida
        - `Verify return code: 21 (unable to verify the first certificate)` → certificado intermediário ausente
    - Procure também por `Verification: OK` para confirmação adicional.
    - Na seção "Certificate chain", verifique o issuer e root (ex.: ISRG Root X1 para Let's Encrypt).

Para um check rápido da validade:
```
echo | openssl s_client -connect hub.saude.go.gov.br:443 -servername hub.saude.go.gov.br 2>/dev/null | openssl x509 -noout -dates
```

### Em Java
Use um snippet simples para testar. Compile e rode com `javac Test.java && java Test`. Ajuste para sua versão de JDK.

```java
import java.net.URI;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public class HttpsTest {
    public static void main(String[] args) {
        String endpoint = "https://hub.saude.go.gov.br";
        try {
            URL url = URI.create(endpoint).toURL();
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.connect();
            int responseCode = conn.getResponseCode();
            System.out.println("Conexão bem-sucedida! Código: " + responseCode);
        } catch (Exception e) {
            System.err.println("Erro: " + e.getMessage());
            // Se for javax.net.ssl.SSLHandshakeException com "PKIX path building failed",
            // é problema de confiança na CA.
            e.printStackTrace();
        }
    }
}
```

- **Erro comum:** `javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path building failed` → CA não confiável.

### Em C# (.NET)
Use um projeto console simples. Rode com `dotnet run` (SDK .NET 10).

```csharp
using System;
using System.Net.Http;
using System.Threading.Tasks;

class Program {
    static async Task Main(string[] args) {
        string endpoint = "https://hub.saude.go.gov.br";
        using var client = new HttpClient();
        try {
            HttpResponseMessage response = await client.GetAsync(endpoint);
            response.EnsureSuccessStatusCode();
            Console.WriteLine("Conexão bem-sucedida! Código: " + response.StatusCode);
        } catch (HttpRequestException e) {
            Console.WriteLine("Erro: " + e.Message);
            // Se for "The SSL connection could not be established" com inner "Authentication failed",
            // é problema de confiança na CA.
            if (e.InnerException != null) {
                Console.WriteLine("Detalhes: " + e.InnerException.Message);
            }
        } catch (Exception ex) {
            Console.WriteLine("Exceção geral: " + ex.Message);
        }
    }
}
```

- **Erro comum:** `System.Net.Http.HttpRequestException: The SSL connection could not be established` → Verifique o inner exception para detalhes de CA.

### Em JavaScript (Node.js)
Rode com `node test.js`. Use Node.js 14+ para melhor suporte a TLS.

```javascript
const https = require('https');

const endpoint = 'https://hub.saude.go.gov.br';

https.get(endpoint, (res) => {
    console.log('Conexão bem-sucedida! Código:', res.statusCode);
}).on('error', (e) => {
    console.error('Erro:', e.message);
    // Se for "Error: unable to verify the first certificate",
    // é problema de confiança na CA.
});
```

- **Erro comum:** `Error: unable to verify the first certificate` ou `DEPTH_ZERO_SELF_SIGNED_CERT` → CA não confiável.

## Resolução de problemas

Se detectar um erro de confiança, o problema geralmente é que a 
CA raiz (atualmente ISRG Root X1 do Let's Encrypt) não está no 
trust store do seu ambiente. Primeiro, 
**descubra o certificado atual da CA**. Depois, importe-o 
manualmente. 

> **Nota**  
> Isso é um workaround para legados; priorize atualizar seu runtime/SO 
> para versões modernas.

### Descobrindo o certificado da CA Raiz do HubSaúde
Use OpenSSL para extrair a cadeia completa e identificar o root:

```
echo | openssl s_client -connect hub.saude.go.gov.br:443 -servername hub.saude.go.gov.br -showcerts 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > chain.pem
```

- Isso salva a cadeia em `chain.pem`.
- Abra o arquivo e procure o último certificado (o root, com "Issuer" igual a "Subject").
- Atualmente, é ISRG Root X1. Baixe o PEM oficial de fontes confiáveis como https://letsencrypt.org/certs/isrgrootx1.pem (verifique sempre o site da CA emitente).

Para automatizar a extração do root:
- Use um editor de texto ou script para isolar o bloco "-BEGIN CERTIFICATE-" do root.

### Importando em Java (JDK/JRE)
Adicione ao trust store `cacerts` (padrão em `$JAVA_HOME/lib/security/cacerts`).

Comando (substitua `root.pem` pelo arquivo do root CA):
```
keytool -import -trustcacerts -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit -noprompt -alias isrgrootx1 -file root.pem
```

- Rode como admin se necessário.
- Verifique: `keytool -list -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit | grep isrgrootx1`.
- Reinicie sua app e teste novamente.

Para apps embed (ex.: em JAR), use um trust store custom via código:
```java
System.setProperty("javax.net.ssl.trustStore", "custom-cacerts");
System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
```

### Importando em .NET (Windows)
Adicione ao store de raízes confiáveis do máquina (para apps .NET Framework/Core).

Via PowerShell (rode como admin; substitua `root.cer` pelo arquivo DER/PEM convertido):
```
Import-Certificate -FilePath "root.cer" -CertStoreLocation Cert:\LocalMachine\Root
```

- Converta PEM para CER se necessário: Use OpenSSL `openssl x509 -outform der -in root.pem -out root.cer`.
- Para .NET Core em Linux/macOS, atualize o trust store do SO (ex.: `update-ca-certificates` no Ubuntu).
- **Não** desabilite a validação de certificado (`ServerCertificateValidationCallback` retornando `true`,
  `DangerousAcceptAnyServerCertificateValidator`, etc.) em produção.
- Integradores do `hubsaude-cliente-csharp` (.NET 10): em homologação ou
  simulador com CA própria, use `SmartTokenClientBuilder.ServerTrustAnchor`
  (caminho PEM ou `X509Certificate2`) em vez de trust-all. Em produção,
  o trust store do runtime já deve conter a CA pública (ex.: Let's Encrypt).

### Importando em JavaScript (Node.js)
Defina a variável de ambiente `NODE_EXTRA_CA_CERTS` para apontar ao arquivo PEM do root.

Exemplo:
```
export NODE_EXTRA_CA_CERTS=/path/to/root.pem
node your-app.js
```

- Ou em código (para https agent custom):
```javascript
const https = require('https');
const fs = require('fs');

const options = {
    ca: [fs.readFileSync('/path/to/root.pem')]
};

https.get('https://hub.saude.go.gov.br', options, (res) => {
    // ...
});
```

- Para apps em produção, inclua o PEM no bundle ou use um pacote como `ssl-root-cas`.

## Considerações finais
- **Atualize:** use runtimes modernos (Java 21+, **.NET 10** neste SDK,
  Node 20+) para evitar problemas de *handshake* TLS. A
  `hubsaude-cliente-java` exige Java 21; a `hubsaude-cliente-csharp`
  exige `net10.0`.
- **Teste em produção:** use ferramentas como SSL Labs (https://www.ssllabs.com/ssltest/) para auditar o servidor.
- **Segurança:** baixe certificados apenas de fontes oficiais para evitar MITM.
- Se persistir problemas, contate o suporte do serviço ou verifique logs do servidor.
