package br.com.bry.challenge.cli;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import br.com.bry.challenge.config.ChallengeProperties;
import br.com.bry.challenge.crypto.DigestService;

/**
 * Executa as etapas práticas do desafio pela linha de comando (perfil {@code cli}) e grava os
 * artefatos de entrega no diretório configurado.
 */
@Component
@Profile("cli")
public class ChallengeStepsRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ChallengeStepsRunner.class);

    private final DigestService digestService;
    private final ChallengeProperties properties;

    public ChallengeStepsRunner(DigestService digestService, ChallengeProperties properties) {
        this.digestService = digestService;
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments args) throws IOException {
        Files.createDirectories(properties.outputDirectory());
        computeDocumentHash();
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
}
