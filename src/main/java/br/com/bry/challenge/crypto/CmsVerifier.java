package br.com.bry.challenge.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.CMSVerifierCertificateNotValidException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Verifica assinaturas CMS attached: a integridade (assinatura e conteúdo) e a confiança do
 * certificado do signatário, além de extrair as informações relevantes da assinatura.
 *
 * <p>Problemas de formato geram {@link CryptoException}; uma assinatura bem formada, mas inválida,
 * gera um {@link VerificationResult} com os motivos da falha.
 *
 * <p>A confiança do certificado é avaliada na data atual: o atributo {@code signingTime} é
 * declarado pelo próprio signatário e, sem um carimbo do tempo, não serve como referência confiável.
 */
@Component
public class CmsVerifier {

    private static final Logger log = LoggerFactory.getLogger(CmsVerifier.class);

    private final DigestService digestService;
    private final CertificateTrustValidator trustValidator;
    private final Provider provider;
    private final Clock clock;

    public CmsVerifier(DigestService digestService, CertificateTrustValidator trustValidator, Provider provider, Clock clock) {
        this.digestService = Objects.requireNonNull(digestService, "digestService");
        this.trustValidator = Objects.requireNonNull(trustValidator, "trustValidator");
        this.provider = Objects.requireNonNull(provider, "provider");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Verifica a assinatura CMS attached. A assinatura pode estar em Base64 (com prioridade, podendo
     * conter quebras de linha) ou em DER (conteúdo binário de um arquivo .p7s).
     */
    public VerificationResult verify(byte[] signature) {
        Objects.requireNonNull(signature, "signature");

        ParsedSignature parsed = parse(decode(signature));
        String documentHash = HexFormat.of().formatHex(digestService.digest(parsed.content(), parsed.digestAlgorithm()));
        List<String> failureReasons = new ArrayList<>();

        if (parsed.signerCertificate() == null) {
            failureReasons.add("O certificado do signatário não foi encontrado na assinatura");
            return new VerificationResult(false, false, null, parsed.signingTime(), parsed.digestAlgorithm(), documentHash, List.of(), failureReasons);
        }

        boolean integrityValid = verifyIntegrity(parsed, failureReasons);
        CertificateTrustValidator.TrustResult trust = trustValidator.validate(parsed.signerCertificate(), parsed.certificates(), clock.instant());
        if (!trust.trusted()) {
            failureReasons.add(trust.failureReason());
        }

        return new VerificationResult(integrityValid, trust.trusted(), parsed.signerCertificate(), parsed.signingTime(),
                parsed.digestAlgorithm(), documentHash, trust.certificationPath(), failureReasons);
    }

    /**
     * Retorna o DER da assinatura: decodifica o conteúdo quando ele é Base64 e, caso contrário,
     * considera que ele já está em DER.
     */
    private static byte[] decode(byte[] signature) {
        // ISO-8859-1 mapeia cada byte para um caractere, de modo que bytes binários (DER) nunca formam Base64 válido
        String base64 = new String(signature, StandardCharsets.ISO_8859_1).replaceAll("\\s", "");
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException notBase64) {
            return signature;
        }
    }

    /**
     * Decodifica a estrutura da assinatura e extrai os dados necessários para a verificação.
     *
     * <p>Exceções relacionadas a estruturas CMS malformadas são convertidas em
     * {@code INVALID_SIGNATURE_FORMAT}, mantendo uma fronteira clara entre erros de formato
     * e assinaturas bem formadas, porém inválidas.
     */
    private ParsedSignature parse(byte[] signature) {
        try {
            CMSSignedData signedData = new CMSSignedData(signature);
            if (signedData.getSignedContent() == null) {
                throw new CryptoException(CryptoErrorCode.INVALID_SIGNATURE_FORMAT,
                        "A assinatura não contém o documento assinado (assinatura detached); é esperada uma assinatura attached");
            }

            Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
            if (signers.size() != 1) {
                throw new CryptoException(CryptoErrorCode.INVALID_SIGNATURE_FORMAT,
                        "A assinatura deve conter exatamente um signatário, mas contém " + signers.size());
            }
            SignerInformation signer = signers.iterator().next();

            List<X509Certificate> signerCertificates = toCertificates(signedData.getCertificates().getMatches(signer.getSID()));
            return new ParsedSignature(
                    signer,
                    signedContent(signedData),
                    MessageDigestUtils.getDigestName(signer.getDigestAlgorithmID().getAlgorithm()),
                    signingTime(signer),
                    toCertificates(signedData.getCertificates().getMatches(null)),
                    signerCertificates.isEmpty() ? null : signerCertificates.get(0));
        } catch (CryptoException e) {
            throw e;
        } catch (CMSException | CertificateException | IOException | RuntimeException e) {
            throw new CryptoException(CryptoErrorCode.INVALID_SIGNATURE_FORMAT, "O conteúdo informado não é uma assinatura CMS válida", e);
        }
    }

    private static byte[] signedContent(CMSSignedData signedData) throws IOException, CMSException {
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        signedData.getSignedContent().write(content);
        return content.toByteArray();
    }

    private static Instant signingTime(SignerInformation signer) {
        AttributeTable signedAttributes = signer.getSignedAttributes();
        Attribute signingTime = signedAttributes == null ? null : signedAttributes.get(CMSAttributes.signingTime);
        if (signingTime == null) {
            return null;
        }
        return Time.getInstance(signingTime.getAttrValues().getObjectAt(0)).getDate().toInstant();
    }

    private static List<X509Certificate> toCertificates(Collection<X509CertificateHolder> holders) throws CertificateException {
        // Usa a implementação padrão da API JCA para manter os certificados como X509Certificate
        // e detectar certificados estruturalmente inválidos durante a conversão.
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        List<X509Certificate> certificates = new ArrayList<>();
        for (X509CertificateHolder holder : holders) {
            certificates.add(converter.getCertificate(holder));
        }
        return certificates;
    }

    /**
     * Confere a assinatura com a chave pública do certificado e valida a integridade
     * do conteúdo por meio do atributo {@code messageDigest}.
     */
    private boolean verifyIntegrity(ParsedSignature parsed, List<String> failureReasons) {
        try {
            boolean valid = parsed.signer().verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(provider).build(parsed.signerCertificate()));
            if (!valid) {
                failureReasons.add("A assinatura não corresponde à chave pública do certificado do signatário");
            }
            return valid;
        } catch (CMSSignerDigestMismatchException e) {
            failureReasons.add("O documento foi alterado: o hash do conteúdo não corresponde ao atributo messageDigest");
        } catch (CMSVerifierCertificateNotValidException e) {
            failureReasons.add("O certificado do signatário não estava válido na data declarada da assinatura");
        } catch (CMSException | OperatorCreationException | RuntimeException e) {
            log.debug("Falha técnica ao verificar a assinatura", e);
            failureReasons.add("Não foi possível verificar a assinatura: a estrutura dos dados assinados é inválida");
        }
        return false;
    }

    /** Dados da assinatura já decodificados e prontos para a verificação. */
    private record ParsedSignature(
            SignerInformation signer,
            byte[] content,
            String digestAlgorithm,
            Instant signingTime,
            List<X509Certificate> certificates,
            X509Certificate signerCertificate) {
    }
}
