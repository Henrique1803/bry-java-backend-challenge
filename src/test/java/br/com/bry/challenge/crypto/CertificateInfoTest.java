package br.com.bry.challenge.crypto;

import static br.com.bry.challenge.support.ChallengeResources.signingCredential;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CertificateInfoTest {

    @Test
    @DisplayName("Extrai titular, emissor, número de série e validade do certificado")
    void extractsCertificateInformation() throws Exception {
        CertificateInfo info = CertificateInfo.from(signingCredential().certificate());

        assertThat(info.subject()).startsWith("CN=HUB2 TESTES,OU=Validado por email,O=BRy Tecnologia");
        assertThat(info.issuer()).endsWith("CN=AC BRy Servidor Seguro v3");
        assertThat(info.serialNumber()).isEqualTo("25F");
        assertThat(info.notBefore()).isEqualTo(Instant.parse("2021-07-21T00:00:00Z"));
        assertThat(info.notAfter()).isEqualTo(Instant.parse("2029-07-21T18:22:00Z"));
    }

    @Test
    @DisplayName("Exibe o e-mail do titular de forma legível, e não como OID")
    void formatsEmailReadably() throws Exception {
        CertificateInfo info = CertificateInfo.from(signingCredential().certificate());

        assertThat(info.subject()).contains("E=darlan@bry.com.br").doesNotContain("1.2.840.113549.1.9.1");
    }
}
