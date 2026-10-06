package br.com.bry.challenge.crypto;

import static br.com.bry.challenge.support.TestCertificates.rsaKeyPair;
import static br.com.bry.challenge.support.TestCertificates.selfSignedCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class SigningCredentialTest {

    @Test
    @DisplayName("Expõe o primeiro certificado da cadeia como certificado do signatário")
    void exposesSignerCertificate() throws Exception {
        KeyPair keyPair = rsaKeyPair();
        X509Certificate signer = selfSignedCertificate(keyPair, "signatario");
        X509Certificate issuer = selfSignedCertificate(rsaKeyPair(), "emissor");

        SigningCredential credential = new SigningCredential(keyPair.getPrivate(), List.of(signer, issuer));

        assertThat(credential.certificate()).isEqualTo(signer);
    }

    @Test
    @DisplayName("Guarda uma cópia imutável da cadeia de certificados")
    void keepsImmutableCopyOfChain() throws Exception {
        KeyPair keyPair = rsaKeyPair();
        List<X509Certificate> chain = new ArrayList<>(List.of(selfSignedCertificate(keyPair, "signatario")));

        SigningCredential credential = new SigningCredential(keyPair.getPrivate(), chain);
        chain.clear();

        assertThat(credential.certificateChain()).hasSize(1);
        assertThatThrownBy(() -> credential.certificateChain().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("Rejeita cadeia de certificados vazia")
    void rejectsEmptyChain() throws Exception {
        KeyPair keyPair = rsaKeyPair();

        assertThatThrownBy(() -> new SigningCredential(keyPair.getPrivate(), List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
