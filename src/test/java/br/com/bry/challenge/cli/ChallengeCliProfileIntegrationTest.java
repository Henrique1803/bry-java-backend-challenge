package br.com.bry.challenge.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.context.WebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Sobe a aplicação com o perfil "cli", gravando os artefatos em um diretório temporário. */
@SpringBootTest
@ActiveProfiles("cli")
class ChallengeCliProfileIntegrationTest {

    @TempDir
    static Path outputDirectory;

    @DynamicPropertySource
    static void challengeProperties(DynamicPropertyRegistry registry) {
        registry.add("challenge.output-directory", () -> outputDirectory.toString());
    }

    @Autowired
    private ApplicationContext context;

    @Test
    @DisplayName("Executa as etapas no perfil cli sem subir o servidor web")
    void runsChallengeStepsWithoutWebServer() {
        assertThat(context).isNotInstanceOf(WebServerApplicationContext.class);
        assertThat(outputDirectory.resolve("doc.txt.sha512")).exists();
        assertThat(outputDirectory.resolve("doc.txt.p7s")).exists();
    }
}
