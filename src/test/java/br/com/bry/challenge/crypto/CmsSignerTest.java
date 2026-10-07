package br.com.bry.challenge.crypto;

import static br.com.bry.challenge.support.ChallengeResources.DOCUMENT;
import static br.com.bry.challenge.support.ChallengeResources.DOCUMENT_SHA_512;
import static br.com.bry.challenge.support.ChallengeResources.signingCredential;
import static br.com.bry.challenge.support.TestCertificates.ecKeyPair;
import static br.com.bry.challenge.support.TestCertificates.selfSignedCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Inspeciona a assinatura gerada diretamente com o BouncyCastle, sem depender do verificador do
 * projeto, para que um erro em um não esconda um erro no outro.
 */
class CmsSignerTest {

    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    /** Momento fixo da assinatura, para que os testes não dependam da data em que são executados. */
    private static final Instant NOW = Instant.parse("2026-10-01T12:00:00Z");

    private static SigningCredential credential;
    private static byte[] document;

    private final CmsSigner signer = new CmsSigner(PROVIDER, Clock.fixed(NOW, ZoneOffset.UTC));

    @BeforeAll
    static void loadChallengeResources() throws Exception {
        credential = signingCredential();
        document = Files.readAllBytes(DOCUMENT);
    }

    @Test
    @DisplayName("Gera assinatura attached, com o conteúdo original dentro da estrutura CMS")
    void embedsOriginalDocument() throws Exception {
        CMSSignedData signedData = new CMSSignedData(signer.sign(document, credential));

        assertThat(signedData.isDetachedSignature()).isFalse();
        assertThat(signedData.getSignedContentTypeOID()).isEqualTo(CMSObjectIdentifiers.data.getId());
        assertThat((byte[]) signedData.getSignedContent().getContent()).isEqualTo(document);
    }

    @Test
    @DisplayName("Usa SHA-512 como algoritmo de hash e RSA como algoritmo de assinatura")
    void usesSha512WithRsa() throws Exception {
        SignerInformation signerInfo = singleSigner(signer.sign(document, credential));

        assertThat(signerInfo.getDigestAlgOID()).isEqualTo(NISTObjectIdentifiers.id_sha512.getId());
        assertThat(signerInfo.getEncryptionAlgOID()).isEqualTo(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId());
    }

    @Test
    @DisplayName("O atributo messageDigest contém o SHA-512 do conteúdo assinado")
    void messageDigestMatchesDocumentHash() throws Exception {
        AttributeTable attributes = singleSigner(signer.sign(document, credential)).getSignedAttributes();

        Attribute messageDigest = attributes.get(CMSAttributes.messageDigest);
        byte[] digest = ASN1OctetString.getInstance(messageDigest.getAttrValues().getObjectAt(0)).getOctets();

        assertThat(HexFormat.of().formatHex(digest)).isEqualTo(DOCUMENT_SHA_512);
    }

    @Test
    @DisplayName("Inclui o atributo assinado signingTime com o momento da assinatura, obtido do relógio da aplicação")
    void includesSigningTime() throws Exception {
        AttributeTable attributes = singleSigner(signer.sign(document, credential)).getSignedAttributes();

        Attribute signingTime = attributes.get(CMSAttributes.signingTime);
        Instant signedAt = Time.getInstance(signingTime.getAttrValues().getObjectAt(0)).getDate().toInstant();

        assertThat(signedAt).isEqualTo(NOW);
    }

    @Test
    @DisplayName("Mantém os atributos assinados padrão: contentType, messageDigest e cmsAlgorithmProtection")
    void keepsStandardSignedAttributes() throws Exception {
        AttributeTable attributes = singleSigner(signer.sign(document, credential)).getSignedAttributes();

        assertThat(attributes.get(CMSAttributes.contentType)).isNotNull();
        assertThat(attributes.get(CMSAttributes.messageDigest)).isNotNull();
        assertThat(attributes.get(CMSAttributes.cmsAlgorithmProtect)).isNotNull();
    }

    @Test
    @DisplayName("Embute o certificado do signatário na assinatura")
    void embedsSignerCertificate() throws Exception {
        CMSSignedData signedData = new CMSSignedData(signer.sign(document, credential));

        X509CertificateHolder embedded = signedData.getCertificates().getMatches(null).iterator().next();

        assertThat(signedData.getCertificates().getMatches(null)).hasSize(1);
        assertThat(embedded.getEncoded()).isEqualTo(credential.certificate().getEncoded());
    }

    @Test
    @DisplayName("A assinatura é criptograficamente válida para a chave pública do certificado")
    void signatureIsCryptographicallyValid() throws Exception {
        SignerInformation signerInfo = singleSigner(signer.sign(document, credential));

        boolean valid = signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder()
                .setProvider(PROVIDER)
                .build(credential.certificate()));

        assertThat(valid).isTrue();
    }

    @Test
    @DisplayName("Codifica a assinatura em DER, com um único signatário")
    void encodesAsDerWithSingleSigner() throws Exception {
        byte[] signature = signer.sign(document, credential);

        assertThat(ASN1Primitive.fromByteArray(signature).getEncoded(ASN1Encoding.DER)).isEqualTo(signature);
        assertThat(new CMSSignedData(signature).getSignerInfos().size()).isEqualTo(1);
    }

    @Test
    @DisplayName("Falha com SIGNATURE_FAILED quando a chave não é compatível com SHA512withRSA")
    void failsWithIncompatibleKey() throws Exception {
        KeyPair ecKeyPair = ecKeyPair();
        X509Certificate certificate = selfSignedCertificate(ecKeyPair, "chave-ec");
        SigningCredential ecCredential = new SigningCredential(ecKeyPair.getPrivate(), List.of(certificate));

        assertThatThrownBy(() -> signer.sign(document, ecCredential))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.SIGNATURE_FAILED);
    }

    private static SignerInformation singleSigner(byte[] signature) throws Exception {
        return new CMSSignedData(signature).getSignerInfos().getSigners().iterator().next();
    }
}
