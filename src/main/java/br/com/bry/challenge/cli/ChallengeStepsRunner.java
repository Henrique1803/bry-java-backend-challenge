package br.com.bry.challenge.cli;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import br.com.bry.challenge.config.ChallengeProperties;
import br.com.bry.challenge.crypto.CmsSigner;
import br.com.bry.challenge.crypto.CmsVerifier;
import br.com.bry.challenge.crypto.DigestService;
import br.com.bry.challenge.crypto.Pkcs12CredentialLoader;
import br.com.bry.challenge.crypto.SigningCredential;
import br.com.bry.challenge.crypto.VerificationResult;

/**
 * Executa as etapas 1, 2 e 3 do desafio pela linha de comando (perfil {@code cli}) e grava os
 * artefatos de entrega no diretório configurado.
 */
@Component
@Profile("cli")
public class ChallengeStepsRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ChallengeStepsRunner.class);

    private final DigestService digestService;
    private final Pkcs12CredentialLoader credentialLoader;
    private final CmsSigner cmsSigner;
    private final CmsVerifier cmsVerifier;
    private final ChallengeProperties properties;

    public ChallengeStepsRunner(DigestService digestService, Pkcs12CredentialLoader credentialLoader, CmsSigner cmsSigner, CmsVerifier cmsVerifier, ChallengeProperties properties) {
        this.digestService = digestService;
        this.credentialLoader = credentialLoader;
        this.cmsSigner = cmsSigner;
        this.cmsVerifier = cmsVerifier;
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments args) throws IOException {
        Files.createDirectories(properties.outputDirectory());
        computeDocumentHash();
        Path signatureFile = signDocument();
        verifySignature(signatureFile);
    }

    /** Etapa 1: calcula o SHA-512 do documento e grava o resultado em hexadecimal. */
    private void computeDocumentHash() throws IOException {
        Path document = properties.document();
        String hash = HexFormat.of().formatHex(digestService.digest(document, DigestService.SHA_512));

        // Mesmo formato do sha512sum, o que permite conferir o resultado com "sha512sum -c"
        Path output = properties.outputDirectory().resolve(document.getFileName() + ".sha512");
        Files.writeString(output, hash + "  " + document + "\n", StandardCharsets.UTF_8);

        log.info("Etapa 1 - Resumo criptográfico (SHA-512)");
        log.info("  Documento: {}", document);
        log.info("  Hash:      {}", hash);
        log.info("  Arquivo:   {}", output);
    }

    /** Etapa 2: assina o documento (CMS attached, SHA512withRSA) e grava a assinatura em .p7s. */
    private Path signDocument() throws IOException {
        Path document = properties.document();
        SigningCredential credential = loadCredential();
        byte[] signature = cmsSigner.sign(Files.readAllBytes(document), credential);

        Path output = properties.outputDirectory().resolve(document.getFileName() + ".p7s");
        Files.write(output, signature);

        log.info("");
        log.info("Etapa 2 - Assinatura digital (CMS attached, {})", CmsSigner.SIGNATURE_ALGORITHM);
        log.info("  Signatário: {}", format(credential.certificate().getSubjectX500Principal()));
        log.info("  Arquivo:    {} ({} bytes)", output, signature.length);
        return output;
    }

    /** Etapa 3: verifica a assinatura gravada na etapa 2 e imprime as informações do signatário. */
    private void verifySignature(Path signatureFile) throws IOException {
        VerificationResult result = cmsVerifier.verify(Files.readAllBytes(signatureFile));
        X509Certificate certificate = result.signerCertificate();

        log.info("");
        log.info("Etapa 3 - Verificação da assinatura ({})", signatureFile);
        log.info("  Integridade:            {}", result.integrityValid());
        log.info("  Certificado confiável:  {}", result.certificateTrusted());
        log.info("  Resultado:              {}", result.valid() ? "VÁLIDA" : "INVÁLIDA");
        log.info("  Data da assinatura:     {}", result.signingTime());
        log.info("  Algoritmo de hash:      {}", result.digestAlgorithm());
        log.info("  Hash do documento:      {}", result.documentHash());
        if (certificate != null) {
            log.info("  Signatário (CN):        {}", result.signerName());
            log.info("  Titular:                {}", format(certificate.getSubjectX500Principal()));
            log.info("  Emissor:                {}", format(certificate.getIssuerX500Principal()));
            log.info("  Número de série:        {}", certificate.getSerialNumber().toString(16).toUpperCase());
            log.info("  Validade:               {} a {}", certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant());
        }
        for (int i = 0; i < result.certificationPath().size(); i++) {
            log.info(i == 0 ? "  Caminho de certificação: {}. {}" : "                          {}. {}",
                    i + 1, format(result.certificationPath().get(i).getSubjectX500Principal()));
        }
        result.failureReasons().forEach(reason -> log.info("  Motivo da falha:        {}", reason));

        if (!result.valid()) {
            throw new IllegalStateException("A assinatura gerada na etapa 2 não passou na verificação da etapa 3");
        }
    }

    /** Formata o nome X.500 de forma legível (inclusive o e-mail, que o Java exibe como OID). */
    private static String format(X500Principal principal) {
        return X500Name.getInstance(principal.getEncoded()).toString();
    }

    private SigningCredential loadCredential() throws IOException {
        ChallengeProperties.Pkcs12 pkcs12 = properties.pkcs12();
        char[] password = pkcs12.password().toCharArray();
        try (InputStream input = Files.newInputStream(pkcs12.path())) {
            return credentialLoader.load(input, password, pkcs12.alias());
        } finally {
            // Remove a senha da memória assim que ela deixa de ser necessária
            Arrays.fill(password, '\0');
        }
    }
}
