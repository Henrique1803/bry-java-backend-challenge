package br.com.bry.challenge.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.DefaultApplicationArguments;

import br.com.bry.challenge.config.ChallengeProperties;
import br.com.bry.challenge.crypto.DigestService;

class ChallengeStepsRunnerTest {

    private static final Path DOCUMENT = Path.of("resources/arquivos/doc.txt");

    private static final String DOCUMENT_SHA_512 =
            "dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b0458"
            + "84fe72111b27cf7d6302916b2691ac7696c1637e1ab44584d8d6613825149e35";

    private final DigestService digestService = new DigestService(new BouncyCastleProvider());

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Etapa 1: grava o hash do documento no formato do sha512sum")
    void writesDocumentHashArtifact() throws Exception {
        Path outputDirectory = tempDir.resolve("artifacts");

        runner(DOCUMENT, outputDirectory).run(new DefaultApplicationArguments());

        Path artifact = outputDirectory.resolve("doc.txt.sha512");
        assertThat(artifact).hasContent(DOCUMENT_SHA_512 + "  " + DOCUMENT);
        assertThat(Files.readString(artifact)).endsWith("\n");
    }

    @Test
    @DisplayName("Falha quando o documento configurado não existe")
    void failsWhenDocumentDoesNotExist() {
        Path missingDocument = tempDir.resolve("inexistente.txt");

        assertThatThrownBy(() -> runner(missingDocument, tempDir).run(new DefaultApplicationArguments()))
                .isInstanceOf(UncheckedIOException.class);
    }

    private ChallengeStepsRunner runner(Path document, Path outputDirectory) {
        return new ChallengeStepsRunner(digestService, new ChallengeProperties(document, outputDirectory));
    }
}
