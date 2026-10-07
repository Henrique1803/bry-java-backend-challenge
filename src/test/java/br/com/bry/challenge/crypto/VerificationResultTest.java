package br.com.bry.challenge.crypto;

import static br.com.bry.challenge.support.TestCertificates.rsaKeyPair;
import static br.com.bry.challenge.support.TestCertificates.selfSignedCertificate;
import static org.assertj.core.api.Assertions.assertThat;

import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class VerificationResultTest {

    @Test
    @DisplayName("Retorna o CN literal do signatário, sem os escapes da representação textual (RFC 4514)")
    void returnsUnescapedSignerName() throws Exception {
        VerificationResult result = resultFor(selfSignedCertificate(rsaKeyPair(), "Silva\\, João"));

        assertThat(result.signerName()).isEqualTo("Silva, João");
    }

    @Test
    @DisplayName("Sem certificado do signatário, o nome é nulo")
    void returnsNullSignerNameWithoutCertificate() {
        assertThat(resultFor(null).signerName()).isNull();
    }

    private static VerificationResult resultFor(X509Certificate certificate) {
        return new VerificationResult(true, true, certificate, null, "SHA-512", "00", List.of(), List.of());
    }
}
