package br.com.bry.challenge.config;

import java.nio.file.Path;

import jakarta.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configurações do desafio (prefixo {@code challenge}), usadas pelo modo CLI.
 *
 * @param document        documento a ser processado nas etapas 1, 2 e 3
 * @param outputDirectory diretório onde os artefatos gerados são gravados
 */
@Validated
@ConfigurationProperties(prefix = "challenge")
public record ChallengeProperties(@NotNull Path document, @NotNull Path outputDirectory) {
}
