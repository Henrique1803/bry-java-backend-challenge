package br.com.bry.challenge.crypto;

import static br.com.bry.challenge.support.ChallengeResources.INTERMEDIATE_CA;
import static br.com.bry.challenge.support.ChallengeResources.ROOT_CA;
import static br.com.bry.challenge.support.ChallengeResources.TRUST_CHAIN_DIRECTORY;
import static br.com.bry.challenge.support.ChallengeResources.readCertificate;
import static br.com.bry.challenge.support.ChallengeResources.signingCredential;
import static br.com.bry.challenge.support.TestCertificates.rsaKeyPair;
import static br.com.bry.challenge.support.TestCertificates.selfSignedCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CertificateTrustValidatorTest {

    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    /** Data fixa dentro da validade do certificado do desafio (2021 a 2029). */
    private static final Instant VALIDATION_TIME = Instant.parse("2026-10-01T12:00:00Z");

    private static X509Certificate signerCertificate;
    private static X509Certificate intermediateCa;
    private static X509Certificate rootCa;

    @BeforeAll
    static void loadChallengeCertificates() throws Exception {
        signerCertificate = signingCredential().certificate();
        intermediateCa = readCertificate(INTERMEDIATE_CA);
        rootCa = readCertificate(ROOT_CA);
    }

    @Test
    @DisplayName("Confia em certificado emitido pela cadeia confiável e retorna o caminho até a AC raiz")
    void trustsChallengeCertificate() {
        CertificateTrustValidator validator = CertificateTrustValidator.fromDirectory(TRUST_CHAIN_DIRECTORY, PROVIDER);

        CertificateTrustValidator.TrustResult result = validator.validate(signerCertificate, List.of(), VALIDATION_TIME);

        assertThat(result.trusted()).isTrue();
        assertThat(result.failureReason()).isNull();
        assertThat(result.certificationPath()).containsExactly(signerCertificate, intermediateCa, rootCa);
    }

    @Test
    @DisplayName("Não confia em certificado autoassinado que não pertence à cadeia")
    void rejectsUnrelatedSelfSignedCertificate() throws Exception {
        CertificateTrustValidator validator = CertificateTrustValidator.fromDirectory(TRUST_CHAIN_DIRECTORY, PROVIDER);
        X509Certificate unrelated = selfSignedCertificate(rsaKeyPair(), "AC desconhecida", VALIDATION_TIME.minus(Duration.ofDays(1)), VALIDATION_TIME.plus(Duration.ofDays(365)));

        CertificateTrustValidator.TrustResult result = validator.validate(unrelated, List.of(), VALIDATION_TIME);

        assertThat(result.trusted()).isFalse();
        assertThat(result.certificationPath()).isEmpty();
        assertThat(result.failureReason()).contains("caminho de certificação");
    }

    @Test
    @DisplayName("Sem a AC intermediária, não é possível formar o caminho até a raiz")
    void rejectsWhenIntermediateIsMissing() {
        CertificateTrustValidator validator = new CertificateTrustValidator(List.of(rootCa), PROVIDER);

        assertThat(validator.validate(signerCertificate, List.of(), VALIDATION_TIME).trusted()).isFalse();
    }

    @Test
    @DisplayName("Usa a AC intermediária embutida na assinatura para completar o caminho até a raiz confiável")
    void usesIntermediateEmbeddedInSignature() {
        CertificateTrustValidator validator = new CertificateTrustValidator(List.of(rootCa), PROVIDER);

        CertificateTrustValidator.TrustResult result = validator.validate(signerCertificate, List.of(intermediateCa), VALIDATION_TIME);

        assertThat(result.trusted()).isTrue();
        assertThat(result.certificationPath()).containsExactly(signerCertificate, intermediateCa, rootCa);
    }

    @Test
    @DisplayName("Não confia no certificado em datas fora do seu período de validade (2021 a 2029)")
    void rejectsOutsideValidityPeriod() {
        CertificateTrustValidator validator = CertificateTrustValidator.fromDirectory(TRUST_CHAIN_DIRECTORY, PROVIDER);

        for (Instant date : List.of(Instant.parse("2020-01-01T00:00:00Z"), Instant.parse("2030-01-01T00:00:00Z"))) {
            CertificateTrustValidator.TrustResult result = validator.validate(signerCertificate, List.of(), date);

            assertThat(result.trusted()).isFalse();
            assertThat(result.failureReason()).contains("período de validade");
        }
    }

    @Test
    @DisplayName("Exige ao menos uma AC raiz (autoassinada) na cadeia confiável")
    void requiresRootCertificate() {
        assertThatThrownBy(() -> new CertificateTrustValidator(List.of(intermediateCa), PROVIDER))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Falha ao carregar a cadeia de um diretório inexistente")
    void failsWithMissingDirectory(@TempDir Path tempDir) {
        assertThatThrownBy(() -> CertificateTrustValidator.fromDirectory(tempDir.resolve("inexistente"), PROVIDER))
                .isInstanceOf(UncheckedIOException.class);
    }

    @Test
    @DisplayName("Falha ao carregar a cadeia quando um arquivo .cer não é um certificado")
    void failsWithInvalidCertificateFile(@TempDir Path tempDir) throws Exception {
        Files.writeString(tempDir.resolve("invalido.cer"), "não é um certificado");

        assertThatThrownBy(() -> CertificateTrustValidator.fromDirectory(tempDir, PROVIDER))
                .isInstanceOf(IllegalStateException.class);
    }
}
