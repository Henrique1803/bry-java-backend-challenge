package br.com.bry.challenge.crypto;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * Dados do signatário: a chave privada e a cadeia de certificados associada a ela.
 *
 * @param privateKey       chave privada usada para assinar
 * @param certificateChain cadeia de certificados, começando pelo certificado do signatário
 */
public record SigningCredential(PrivateKey privateKey, List<X509Certificate> certificateChain) {

    public SigningCredential {
        Objects.requireNonNull(privateKey, "privateKey");
        certificateChain = List.copyOf(certificateChain);
        if (certificateChain.isEmpty()) {
            throw new IllegalArgumentException("A cadeia de certificados não pode ser vazia");
        }
    }

    /** Certificado do signatário (primeiro da cadeia). */
    public X509Certificate certificate() {
        return certificateChain.get(0);
    }
}
