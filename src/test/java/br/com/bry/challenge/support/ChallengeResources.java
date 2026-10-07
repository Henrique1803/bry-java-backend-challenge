package br.com.bry.challenge.support;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import br.com.bry.challenge.crypto.Pkcs12CredentialLoader;
import br.com.bry.challenge.crypto.SigningCredential;

/** Artefatos fornecidos pelo desafio e valores de referência usados nos testes. */
public final class ChallengeResources {

    /** Documento a ser processado nas etapas 1, 2 e 3. */
    public static final Path DOCUMENT = Path.of("resources/arquivos/doc.txt");

    /** SHA-512 do documento, obtido de forma independente com {@code sha512sum}. */
    public static final String DOCUMENT_SHA_512 =
            "dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b0458"
            + "84fe72111b27cf7d6302916b2691ac7696c1637e1ab44584d8d6613825149e35";

    /** PKCS12 com a chave privada e o certificado do signatário. */
    public static final Path PKCS12 = Path.of("resources/pkcs12/certificado_teste_hub.pfx");

    /** Alias da chave privada no PKCS12. */
    public static final String PKCS12_ALIAS = "{e2618a8b-20de-4dd2-b209-70912e3177f4}";

    /** Diretório com os certificados da cadeia confiável (AC intermediária e AC raiz). */
    public static final Path TRUST_CHAIN_DIRECTORY = Path.of("resources/cadeia");

    /** AC raiz da cadeia confiável. */
    public static final Path ROOT_CA = TRUST_CHAIN_DIRECTORY.resolve("ac_raiz_bry_v3.cer");

    /** AC intermediária, emissora do certificado do signatário. */
    public static final Path INTERMEDIATE_CA = TRUST_CHAIN_DIRECTORY.resolve("ac_bry_servidor_seguro_v3.cer");

    private ChallengeResources() {
    }

    /** Senha do PKCS12. Retorna uma cópia nova a cada chamada, pois quem a recebe pode zerá-la. */
    public static char[] pkcs12Password() {
        return "bry123456".toCharArray();
    }

    /** Carrega a credencial do signatário a partir do PKCS12 do desafio. */
    public static SigningCredential signingCredential() throws IOException {
        try (InputStream input = Files.newInputStream(PKCS12)) {
            return new Pkcs12CredentialLoader().load(input, pkcs12Password(), PKCS12_ALIAS);
        }
    }

    /** Lê um certificado X.509 (DER ou PEM). */
    public static X509Certificate readCertificate(Path file) throws Exception {
        try (InputStream input = Files.newInputStream(file)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
    }
}
