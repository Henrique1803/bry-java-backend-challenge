package br.com.bry.challenge.crypto;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

/**
 * Resultado da verificação de uma assinatura CMS.
 *
 * @param integrityValid     se a assinatura confere com o conteúdo e com a chave do certificado
 * @param certificateTrusted se o certificado do signatário é confiável na cadeia configurada
 * @param signerCertificate  certificado do signatário (nulo se não estiver na assinatura)
 * @param signingTime        atributo assinado signingTime (nulo se ausente)
 * @param digestAlgorithm    algoritmo de hash usado na assinatura (por exemplo, SHA-512)
 * @param documentHash       hash do conteúdo assinado, em hexadecimal
 * @param certificationPath  caminho do certificado até a AC raiz (vazio se não confiável)
 * @param failureReasons     motivos pelos quais a assinatura não é válida
 */
public record VerificationResult(
        boolean integrityValid,
        boolean certificateTrusted,
        X509Certificate signerCertificate,
        Instant signingTime,
        String digestAlgorithm,
        String documentHash,
        List<X509Certificate> certificationPath,
        List<String> failureReasons) {

    public VerificationResult {
        certificationPath = List.copyOf(certificationPath);
        failureReasons = List.copyOf(failureReasons);
    }

    /** A assinatura é válida quando está íntegra e o certificado do signatário é confiável. */
    public boolean valid() {
        return integrityValid && certificateTrusted;
    }

    /** Nome do signatário: atributo CN do certificado (nulo se indisponível). */
    public String signerName() {
        if (signerCertificate == null) {
            return null;
        }
        RDN[] commonNames = X500Name.getInstance(signerCertificate.getSubjectX500Principal().getEncoded()).getRDNs(BCStyle.CN);
        if (commonNames.length == 0) {
            return null;
        }
        // Valor literal do CN, sem os escapes da representação textual (RFC 4514)
        ASN1Encodable value = commonNames[0].getFirst().getValue();
        return value instanceof ASN1String text ? text.getString() : IETFUtils.valueToString(value);
    }
}
