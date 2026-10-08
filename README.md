# Desafio técnico Bry — Back-end Java

Projeto desenvolvido para o desafio prático da vaga de Desenvolvedor Back-end Java.

A aplicação calcula o hash SHA-512 de um documento, gera uma assinatura digital CMS attached (SHA-512 com RSA), verifica a assinatura (integridade e cadeia de confiança) e disponibiliza essas operações em uma API REST.

O relatório técnico está em [`docs/relatorio-henrique-mateus-teodoro.pdf`](docs/relatorio-henrique-mateus-teodoro.pdf).

## Tecnologias

- Java 17 (17.0.20)
- Spring Boot 3.5.16
- BouncyCastle 1.86 (`bcprov-jdk18on` e `bcpkix-jdk18on`)
- Maven, com Maven Wrapper
- JUnit 5, AssertJ, MockMvc e JaCoCo
- Docker e Docker Compose
- GitHub Actions

O projeto foi desenvolvido em Linux (Ubuntu 24.04).

## Requisitos

Uma das opções abaixo:

- **Docker** (com Docker Compose), sem precisar de Java instalado; ou
- **Java 17**. O Maven não precisa estar instalado, pois o projeto usa o Maven Wrapper (`./mvnw`).

## Estrutura do projeto

```text
.
├── artifacts/                  Resultados das etapas 1 e 2 (entregáveis)
├── docs/                       Relatório e coleção do Postman
├── resources/
│   ├── arquivos/               Documento do desafio (doc.txt)
│   ├── cadeia/                 Certificados da cadeia confiável (AC raiz e intermediária)
│   └── pkcs12/                 Certificado e chave privada de teste
├── src/main/java/br/com/bry/challenge/
│   ├── api/                    Endpoints REST, resposta da verificação e tratamento de erros
│   ├── cli/                    Execução das etapas 1, 2 e 3 pela linha de comando
│   ├── config/                 Configurações da aplicação
│   └── crypto/                 Hash, PKCS12, assinatura e verificação CMS
├── src/test/java/              Testes de unidade e de integração
├── .github/workflows/          CI e release
├── Dockerfile                  Build e execução em container
├── compose.yaml                Serviços da API e da CLI
└── pom.xml                     Dependências e build
```

## Execução com Docker

Subir a API na porta `8080`:

```bash
docker compose up --build
```

A imagem é construída a partir do `Dockerfile`: a compilação e os testes rodam dentro do container, e a imagem final contém apenas o JRE e a aplicação.

Executar as etapas 1, 2 e 3 (os arquivos são gravados em `artifacts/`):

```bash
docker compose run --rm cli
```

A imagem também é publicada no GitHub Container Registry a cada release:

```bash
docker run -p 8080:8080 ghcr.io/henrique1803/bry-java-backend-challenge:1.0.0
```

## Execução sem Docker

Compilar e rodar os testes:

```bash
./mvnw clean verify
```

Subir a API:

```bash
./mvnw spring-boot:run
```

Executar as etapas 1, 2 e 3:

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=cli
```

Também é possível usar o jar gerado em `target/` (ou baixado da aba Releases):

```bash
java -jar target/bry-java-backend-challenge-1.0.0.jar
java -jar target/bry-java-backend-challenge-1.0.0.jar --spring.profiles.active=cli
```

Os comandos devem ser executados a partir da raiz do projeto, pois os caminhos dos arquivos do desafio são relativos a ela.

## Etapas 1, 2 e 3 (CLI)

No perfil `cli`, a aplicação não sobe o servidor: executa as três etapas em sequência e encerra.

1. calcula o SHA-512 de `resources/arquivos/doc.txt`;
2. assina o documento com o certificado de `resources/pkcs12/certificado_teste_hub.pfx`;
3. verifica a assinatura gerada e imprime as informações do signatário.

Resultados gravados:

```text
artifacts/doc.txt.sha512    Hash SHA-512 em hexadecimal (etapa 1)
artifacts/doc.txt.p7s       Assinatura CMS attached em DER (etapa 2)
```

O hash pode ser conferido com `sha512sum -c artifacts/doc.txt.sha512`. A cada execução uma nova assinatura é gerada, pois a data da assinatura (`signingTime`) muda.

Saída da etapa 3 (resumida):

```text
Etapa 3 - Verificação da assinatura (artifacts/doc.txt.p7s)
  Integridade:            true
  Certificado confiável:  true
  Resultado:              VÁLIDA
  Algoritmo de hash:      SHA-512
  Hash do documento:      dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b0458...
  Signatário (CN):        HUB2 TESTES
  Emissor:                C=BR,O=BRy Tecnologia SA,...,CN=AC BRy Servidor Seguro v3
  Caminho de certificação: 1. CN=HUB2 TESTES,...
                          2. ...CN=AC BRy Servidor Seguro v3
                          3. ...CN=Autoridade Certificadora Raiz BRy Tecnologia v3
```

## API REST

### `POST /signature/`

Assina um arquivo e retorna a assinatura CMS attached em Base64 (`text/plain`).

| Campo (multipart/form-data) | Conteúdo |
|---|---|
| `file` | arquivo a ser assinado |
| `pkcs12` | arquivo PKCS12 (`.pfx`/`.p12`) com a chave privada e o certificado |
| `password` | senha do arquivo PKCS12 |

```bash
curl -F file=@resources/arquivos/doc.txt \
     -F pkcs12=@resources/pkcs12/certificado_teste_hub.pfx \
     -F password=bry123456 \
     http://localhost:8080/signature/ -o assinatura.b64
```

### `POST /verify/`

Verifica uma assinatura CMS attached. Recebe o arquivo assinado no campo `signature`, em Base64. Também aceita o arquivo `.p7s` binário (DER).

```bash
curl -F signature=@assinatura.b64 http://localhost:8080/verify/
```

Resposta:

```json
{
  "status": "VALIDO",
  "infos": {
    "signerName": "HUB2 TESTES",
    "signingTime": "2026-10-07T03:43:40Z",
    "documentHash": "dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b0458...",
    "digestAlgorithm": "SHA-512"
  },
  "details": {
    "integrityValid": true,
    "certificateTrusted": true,
    "certificate": {
      "subject": "CN=HUB2 TESTES,OU=Validado por email,O=BRy Tecnologia,...",
      "issuer": "C=BR,O=BRy Tecnologia SA,...,CN=AC BRy Servidor Seguro v3",
      "serialNumber": "25F",
      "notBefore": "2021-07-21T00:00:00Z",
      "notAfter": "2029-07-21T18:22:00Z"
    },
    "certificationPath": ["CN=HUB2 TESTES,...", "...CN=AC BRy Servidor Seguro v3", "...CN=Autoridade Certificadora Raiz BRy Tecnologia v3"],
    "failureReasons": []
  }
}
```

- `status` é `VALIDO` quando a assinatura está íntegra **e** o certificado do signatário é confiável na cadeia de `resources/cadeia`. Caso contrário, é `INVALIDO`, e os motivos aparecem em `details.failureReasons`.
- `infos` traz as informações pedidas no enunciado: nome do signatário (CN), data da assinatura (`signingTime`), hash do documento em hexadecimal e algoritmo de hash.
- `details` traz informações adicionais da verificação.
- Uma assinatura bem formada, mas inválida (documento alterado, certificado não confiável), retorna HTTP 200 com `INVALIDO`.

### Erros

Os erros seguem o formato Problem Details (RFC 9457), com o campo `code`:

```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "detail": "Senha do PKCS12 incorreta",
  "instance": "/signature/",
  "code": "INVALID_PASSWORD"
}
```

| HTTP | `code` | Situação |
|---|---|---|
| 400 | `MISSING_FIELD` | campo obrigatório ausente |
| 400 | `EMPTY_FILE` | arquivo a ser assinado vazio |
| 400 | `INVALID_PKCS12` | arquivo PKCS12 inválido ou corrompido |
| 400 | `INVALID_PASSWORD` | senha do PKCS12 incorreta |
| 400 | `PRIVATE_KEY_NOT_FOUND` | PKCS12 sem chave privada ou com mais de uma |
| 400 | `UNSUPPORTED_KEY` | chave privada que não é RSA |
| 400 | `INVALID_SIGNATURE_FORMAT` | conteúdo que não é uma assinatura CMS attached |
| 400 | `UNSUPPORTED_ALGORITHM` | algoritmo de hash não suportado |
| 413 | `FILE_TOO_LARGE` | arquivo acima de 10 MB |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | requisição que não é `multipart/form-data` |
| 500 | `SIGNATURE_FAILED` | falha ao gerar a assinatura |
| 500 | `INTERNAL_ERROR` | erro inesperado (os detalhes ficam apenas no log) |

### Postman

A coleção [`docs/bry-challenge.postman_collection.json`](docs/bry-challenge.postman_collection.json) tem as duas requisições prontas.

## Testes

```bash
./mvnw clean verify
```

São 94 testes (75 de unidade e 19 de integração). O build falha se a cobertura ficar abaixo de 90% das linhas ou 80% dos branches. O relatório de cobertura do JaCoCo é gerado em `target/site/jacoco/index.html`.

## Configuração

Os caminhos e a senha usados pela CLI ficam em `src/main/resources/application.yml` e podem ser alterados por argumento ou variável de ambiente:

| Propriedade | Padrão |
|---|---|
| `challenge.trust-chain-directory` | `resources/cadeia` |
| `challenge.document` | `resources/arquivos/doc.txt` |
| `challenge.output-directory` | `artifacts` |
| `challenge.pkcs12.path` | `resources/pkcs12/certificado_teste_hub.pfx` |
| `challenge.pkcs12.alias` | `{e2618a8b-20de-4dd2-b209-70912e3177f4}` |
| `challenge.pkcs12.password` | `bry123456` |

Exemplo: `--challenge.pkcs12.password=...` ou `CHALLENGE_PKCS12_PASSWORD=...`.

## Integração contínua e release

A cada push, o GitHub Actions:

- compila, roda os testes e confere a cobertura;
- executa as etapas 1, 2 e 3 e confere os resultados com `sha512sum` e `openssl cms -verify`;
- constrói a imagem Docker, sobe o container e testa os endpoints `/signature/` e `/verify/`.

Ao enviar uma tag `vX.Y.Z` (igual à versão do `pom.xml`), o pipeline roda a CI e, se tudo passar, publica na aba Releases o jar e os arquivos das etapas 1 e 2, e publica a imagem no GitHub Container Registry.
