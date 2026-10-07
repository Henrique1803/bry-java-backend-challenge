package br.com.bry.challenge.cli;

import static br.com.bry.challenge.support.ChallengeResources.DOCUMENT;
import static br.com.bry.challenge.support.ChallengeResources.DOCUMENT_SHA_512;
import static br.com.bry.challenge.support.ChallengeResources.PKCS12;
import static br.com.bry.challenge.support.ChallengeResources.PKCS12_ALIAS;
import static br.com.bry.challenge.support.ChallengeResources.pkcs12Password;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.DefaultApplicationArguments;

import br.com.bry.challenge.config.ChallengeProperties;
import br.com.bry.challenge.crypto.CmsSigner;
import br.com.bry.challenge.crypto.CryptoErrorCode;
import br.com.bry.challenge.crypto.CryptoException;
import br.com.bry.challenge.crypto.DigestService;
import br.com.bry.challenge.crypto.Pkcs12CredentialLoader;

class ChallengeStepsRunnerTest {

    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Etapa 1: grava o hash do documento no formato do sha512sum")
    void writesDocumentHashArtifact() throws Exception {
        Path outputDirectory = tempDir.resolve("artifacts");

        runner(DOCUMENT, outputDirectory, new String(pkcs12Password())).run(new DefaultApplicationArguments());

        Path artifact = outputDirectory.resolve("doc.txt.sha512");
        assertThat(artifact).hasContent(DOCUMENT_SHA_512 + "  " + DOCUMENT);
        assertThat(Files.readString(artifact)).endsWith("\n");
    }

    @Test
    @DisplayName("Etapa 2: grava a assinatura CMS attached do documento em .p7s")
    void writesSignatureArtifact() throws Exception {
        Path outputDirectory = tempDir.resolve("artifacts");

        runner(DOCUMENT, outputDirectory, new String(pkcs12Password())).run(new DefaultApplicationArguments());

        CMSSignedData signedData = new CMSSignedData(Files.readAllBytes(outputDirectory.resolve("doc.txt.p7s")));
        assertThat((byte[]) signedData.getSignedContent().getContent()).isEqualTo(Files.readAllBytes(DOCUMENT));
        assertThat(signedData.getSignerInfos().size()).isEqualTo(1);
    }

    @Test
    @DisplayName("Falha quando o documento configurado não existe")
    void failsWhenDocumentDoesNotExist() {
        Path missingDocument = tempDir.resolve("inexistente.txt");

        assertThatThrownBy(() -> runner(missingDocument, tempDir, new String(pkcs12Password())).run(new DefaultApplicationArguments()))
                .isInstanceOf(UncheckedIOException.class);
    }

    @Test
    @DisplayName("Falha com INVALID_PASSWORD quando a senha configurada do PKCS12 está incorreta")
    void failsWithWrongPkcs12Password() {
        assertThatThrownBy(() -> runner(DOCUMENT, tempDir, "senha-errada").run(new DefaultApplicationArguments()))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.INVALID_PASSWORD);
    }

    private static ChallengeStepsRunner runner(Path document, Path outputDirectory, String pkcs12Password) {
        ChallengeProperties properties = new ChallengeProperties(document, outputDirectory,
                new ChallengeProperties.Pkcs12(PKCS12, PKCS12_ALIAS, pkcs12Password));
        return new ChallengeStepsRunner(new DigestService(PROVIDER), new Pkcs12CredentialLoader(),
                new CmsSigner(PROVIDER), properties);
    }
}
