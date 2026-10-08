package br.com.bry.challenge.crypto;

import java.security.cert.X509Certificate;
import java.time.Instant;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;

/**
 * Informações de um certificado X.509 em formato legível, usadas na apresentação do resultado da
 * verificação (linha de comando e API).
 *
 * @param subject      titular do certificado
 * @param issuer       emissor do certificado
 * @param serialNumber número de série em hexadecimal
 * @param notBefore    início da validade
 * @param notAfter     fim da validade
 */
public record CertificateInfo(String subject, String issuer, String serialNumber, Instant notBefore, Instant notAfter) {

    public static CertificateInfo from(X509Certificate certificate) {
        return new CertificateInfo(
                format(certificate.getSubjectX500Principal()),
                format(certificate.getIssuerX500Principal()),
                certificate.getSerialNumber().toString(16).toUpperCase(),
                certificate.getNotBefore().toInstant(),
                certificate.getNotAfter().toInstant());
    }

    /** Formata o nome X.500 pelo BouncyCastle, que exibe o e-mail como {@code E=} (o Java o exibe como OID). */
    private static String format(X500Principal principal) {
        return X500Name.getInstance(principal.getEncoded()).toString();
    }
}
