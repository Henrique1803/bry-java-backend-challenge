package br.com.bry.challenge.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Objects;

import org.springframework.stereotype.Component;

/**
 * Calcula resumos criptográficos (hash) com o provider BouncyCastle.
 *
 * <p>Todo cálculo passa por {@link #digest(InputStream, String)}, que lê a entrada em blocos
 * (sem carregá-la inteira em memória). As demais sobrecargas apenas adaptam a origem dos dados.
 */
@Component
public class DigestService {

    public static final String SHA_512 = "SHA-512";

    private final Provider provider;

    public DigestService(Provider provider) {
        this.provider = Objects.requireNonNull(provider, "provider");
    }

    /**
     * Calcula o hash do conteúdo do stream. O stream não é fechado, pois pertence a quem chamou.
     */
    public byte[] digest(InputStream input, String algorithm) {
        Objects.requireNonNull(input, "input");
        MessageDigest messageDigest = createMessageDigest(algorithm);
        try {
            new DigestInputStream(input, messageDigest).transferTo(OutputStream.nullOutputStream());
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao ler os dados para o cálculo do hash", e);
        }
        return messageDigest.digest();
    }

    public byte[] digest(byte[] data, String algorithm) {
        Objects.requireNonNull(data, "data");
        return digest(new ByteArrayInputStream(data), algorithm);
    }

    public byte[] digest(Path file, String algorithm) {
        Objects.requireNonNull(file, "file");
        try (InputStream input = Files.newInputStream(file)) {
            return digest(input, algorithm);
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao ler o arquivo " + file, e);
        }
    }

    private MessageDigest createMessageDigest(String algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        try {
            return MessageDigest.getInstance(algorithm, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(CryptoErrorCode.UNSUPPORTED_ALGORITHM,
                    "Algoritmo de hash não suportado: " + algorithm, e);
        }
    }
}
