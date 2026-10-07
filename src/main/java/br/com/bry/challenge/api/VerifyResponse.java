package br.com.bry.challenge.api;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;

import br.com.bry.challenge.crypto.VerificationResult;

/**
 * Resposta do endpoint {@code /verify/}.
 *
 * @param status  VALIDO quando a assinatura está íntegra e o certificado do signatário é confiável
 * @param infos   informações obrigatórias da assinatura
 * @param details informações adicionais da verificação
 */
public record VerifyResponse(Status status, Infos infos, Details details) {

    public enum Status {
        VALIDO,
        INVALIDO
    }

    /**
     * @param signerName      nome do signatário (atributo CN do certificado)
     * @param signingTime     data da assinatura (atributo signingTime)
     * @param documentHash    hash do documento (conteúdo de encapContentInfo), em hexadecimal
     * @param digestAlgorithm nome do algoritmo de hash (atributo digestAlgorithm)
     */
    public record Infos(String signerName, Instant signingTime, String documentHash, String digestAlgorithm) {
    }

    /**
     * @param integrityValid     se a assinatura confere com o conteúdo e com a chave do certificado
     * @param certificateTrusted se o certificado do signatário é confiável na cadeia configurada
     * @param certificate        dados do certificado do signatário (nulo se ausente na assinatura)
     * @param certificationPath  titulares dos certificados do caminho até a AC raiz
     * @param failureReasons     motivos pelos quais a assinatura é inválida
     */
    public record Details(boolean integrityValid, boolean certificateTrusted, CertificateInfo certificate,
                          List<String> certificationPath, List<String> failureReasons) {
    }

    public record CertificateInfo(String subject, String issuer, String serialNumber, Instant notBefore, Instant notAfter) {

        static CertificateInfo from(X509Certificate certificate) {
            return new CertificateInfo(
                    format(certificate.getSubjectX500Principal()),
                    format(certificate.getIssuerX500Principal()),
                    certificate.getSerialNumber().toString(16).toUpperCase(),
                    certificate.getNotBefore().toInstant(),
                    certificate.getNotAfter().toInstant());
        }
    }

    public static VerifyResponse from(VerificationResult result) {
        X509Certificate certificate = result.signerCertificate();
        return new VerifyResponse(
                result.valid() ? Status.VALIDO : Status.INVALIDO,
                new Infos(result.signerName(), result.signingTime(), result.documentHash(), result.digestAlgorithm()),
                new Details(
                        result.integrityValid(),
                        result.certificateTrusted(),
                        certificate == null ? null : CertificateInfo.from(certificate),
                        result.certificationPath().stream().map(c -> format(c.getSubjectX500Principal())).toList(),
                        result.failureReasons()));
    }

    /** Nome X.500 legível (inclusive o e-mail, que o Java exibe como OID). */
    private static String format(X500Principal principal) {
        return X500Name.getInstance(principal.getEncoded()).toString();
    }
}
