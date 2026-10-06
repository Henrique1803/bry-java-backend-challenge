package br.com.bry.challenge.crypto;

import static br.com.bry.challenge.support.ChallengeResources.DOCUMENT;
import static br.com.bry.challenge.support.ChallengeResources.DOCUMENT_SHA_512;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DigestServiceTest {


    private static final HexFormat HEX = HexFormat.of();

    private final DigestService digestService = new DigestService(new BouncyCastleProvider());

    @Test
    @DisplayName("Calcula o SHA-512 de \"abc\" conforme o vetor de teste do NIST (FIPS 180-2)")
    void computesNistVectorForAbc() {
        byte[] hash = digestService.digest("abc".getBytes(StandardCharsets.US_ASCII), DigestService.SHA_512);

        assertThat(HEX.formatHex(hash)).isEqualTo(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    }

    @Test
    @DisplayName("Calcula o SHA-512 de uma entrada vazia")
    void computesHashOfEmptyInput() {
        byte[] hash = digestService.digest(new byte[0], DigestService.SHA_512);

        assertThat(HEX.formatHex(hash)).isEqualTo(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    @Test
    @DisplayName("Etapa 1: calcula o SHA-512 do documento doc.txt")
    void computesHashOfChallengeDocument() {
        byte[] hash = digestService.digest(DOCUMENT, DigestService.SHA_512);

        assertThat(hash).hasSize(64);
        assertThat(HEX.formatHex(hash)).isEqualTo(DOCUMENT_SHA_512);
    }

    @Test
    @DisplayName("Arquivo, bytes em memória e stream produzem o mesmo hash")
    void allInputSourcesProduceSameHash() throws Exception {
        byte[] content = Files.readAllBytes(DOCUMENT);

        byte[] fromFile = digestService.digest(DOCUMENT, DigestService.SHA_512);
        byte[] fromBytes = digestService.digest(content, DigestService.SHA_512);
        byte[] fromStream = digestService.digest(new ByteArrayInputStream(content), DigestService.SHA_512);

        assertThat(fromBytes).isEqualTo(fromFile);
        assertThat(fromStream).isEqualTo(fromFile);
    }

    @Test
    @DisplayName("Processa em streaming entradas maiores que o buffer interno, com resultado igual ao do JDK")
    void streamsLargeInput() throws Exception {
        byte[] content = new byte[1024 * 1024 + 7];
        new Random(42).nextBytes(content);
        byte[] expected = MessageDigest.getInstance(DigestService.SHA_512, "SUN").digest(content);

        byte[] hash = digestService.digest(new ByteArrayInputStream(content), DigestService.SHA_512);

        assertThat(hash).isEqualTo(expected);
    }

    @Test
    @DisplayName("Aceita outros algoritmos de hash, como o SHA-256")
    void supportsOtherAlgorithms() {
        byte[] hash = digestService.digest("abc".getBytes(StandardCharsets.US_ASCII), "SHA-256");

        assertThat(HEX.formatHex(hash))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    @DisplayName("Rejeita algoritmo inexistente com erro de domínio UNSUPPORTED_ALGORITHM")
    void rejectsUnsupportedAlgorithm() {
        assertThatThrownBy(() -> digestService.digest(new byte[] {1, 2, 3}, "SHA-999"))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.UNSUPPORTED_ALGORITHM)
                .hasMessageContaining("SHA-999");
    }

    @Test
    @DisplayName("Falha com erro de leitura quando o arquivo não existe")
    void failsWhenFileDoesNotExist(@TempDir Path tempDir) {
        Path missingFile = tempDir.resolve("inexistente.txt");

        assertThatThrownBy(() -> digestService.digest(missingFile, DigestService.SHA_512))
                .isInstanceOf(UncheckedIOException.class)
                .hasMessageContaining("inexistente.txt")
                .hasCauseInstanceOf(NoSuchFileException.class);
    }

    @Test
    @DisplayName("Converte falha de leitura do stream em UncheckedIOException, preservando a causa")
    void wrapsStreamReadFailure() {
        IOException readFailure = new IOException("disco indisponível");
        InputStream failingStream = new InputStream() {
            @Override
            public int read() throws IOException {
                throw readFailure;
            }
        };

        assertThatThrownBy(() -> digestService.digest(failingStream, DigestService.SHA_512))
                .isInstanceOf(UncheckedIOException.class)
                .hasCause(readFailure);
    }
}
