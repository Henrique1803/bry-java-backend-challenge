package br.com.bry.challenge.config;

import java.nio.file.Path;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configurações do desafio (prefixo {@code challenge}).
 *
 * @param document            documento a ser processado nas etapas 1, 2 e 3 (modo CLI)
 * @param outputDirectory     diretório onde os artefatos gerados são gravados (modo CLI)
 * @param pkcs12              arquivo PKCS12 com a chave privada e o certificado do signatário (modo CLI)
 * @param trustChainDirectory diretório com os certificados da cadeia confiável (CLI e API)
 */
@Validated
@ConfigurationProperties(prefix = "challenge")
public record ChallengeProperties(
        @NotNull Path document,
        @NotNull Path outputDirectory,
        @Valid @NotNull Pkcs12 pkcs12,
        @NotNull Path trustChainDirectory) {

    /**
     * @param path     caminho do arquivo PKCS12
     * @param alias    alias da chave privada no arquivo
     * @param password senha do arquivo
     */
    public record Pkcs12(@NotNull Path path, @NotBlank String alias, @NotBlank String password) {
    }
}
