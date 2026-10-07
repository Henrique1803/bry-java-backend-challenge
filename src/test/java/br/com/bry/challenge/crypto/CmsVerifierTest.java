package br.com.bry.challenge.crypto;

import static br.com.bry.challenge.support.ChallengeResources.DOCUMENT;
import static br.com.bry.challenge.support.ChallengeResources.DOCUMENT_SHA_512;
import static br.com.bry.challenge.support.ChallengeResources.TRUST_CHAIN_DIRECTORY;
import static br.com.bry.challenge.support.ChallengeResources.signingCredential;
import static br.com.bry.challenge.support.TestCertificates.rsaKeyPair;
import static br.com.bry.challenge.support.TestCertificates.selfSignedCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class CmsVerifierTest {

    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    /** Data fixa (de assinatura e de verificação) dentro da validade do certificado do desafio. */
    private static final Instant NOW = Instant.parse("2026-10-01T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private static SigningCredential credential;
    private static byte[] document;
    private static CmsVerifier verifier;

    private final CmsSigner signer = new CmsSigner(PROVIDER, CLOCK);

    @BeforeAll
    static void setUp() throws Exception {
        credential = signingCredential();
        document = Files.readAllBytes(DOCUMENT);
        verifier = verifierAt(CLOCK);
    }

    @Test
    @DisplayName("Valida assinatura íntegra de signatário confiável e extrai as informações da assinatura")
    void verifiesValidSignature() {
        VerificationResult result = verifier.verify(signer.sign(document, credential));

        assertThat(result.integrityValid()).isTrue();
        assertThat(result.certificateTrusted()).isTrue();
        assertThat(result.valid()).isTrue();
        assertThat(result.failureReasons()).isEmpty();
        assertThat(result.signerName()).isEqualTo("HUB2 TESTES");
        assertThat(result.signerCertificate()).isEqualTo(credential.certificate());
        assertThat(result.signingTime()).isEqualTo(NOW);
        assertThat(result.digestAlgorithm()).isEqualTo("SHA-512");
        assertThat(result.documentHash()).isEqualTo(DOCUMENT_SHA_512);
        assertThat(result.certificationPath()).hasSize(3);
    }

    @Test
    @DisplayName("Detecta documento alterado (1 byte do conteúdo modificado dentro do .p7s)")
    void detectsTamperedContent() {
        byte[] signature = signer.sign(document, credential);
        signature[indexOf(signature, document)] ^= 0x01;

        VerificationResult result = verifier.verify(signature);

        assertThat(result.integrityValid()).isFalse();
        assertThat(result.valid()).isFalse();
        assertThat(result.failureReasons()).anyMatch(reason -> reason.contains("documento foi alterado"));
    }

    @Test
    @DisplayName("Detecta assinatura RSA alterada (último byte do .p7s modificado)")
    void detectsTamperedSignatureValue() {
        byte[] signature = signer.sign(document, credential);
        signature[signature.length - 1] ^= 0x01;

        VerificationResult result = verifier.verify(signature);

        assertThat(result.integrityValid()).isFalse();
        assertThat(result.failureReasons()).anyMatch(reason -> reason.contains("chave pública"));
    }

    @Test
    @DisplayName("Detecta assinatura feita com uma chave que não corresponde ao certificado embutido")
    void detectsKeyThatDoesNotMatchCertificate() throws Exception {
        SigningCredential impostor = new SigningCredential(rsaKeyPair().getPrivate(), credential.certificateChain());

        VerificationResult result = verifier.verify(signer.sign(document, impostor));

        assertThat(result.integrityValid()).isFalse();
        assertThat(result.certificateTrusted()).isTrue();
        assertThat(result.valid()).isFalse();
    }

    @Test
    @DisplayName("Assinatura íntegra, mas com certificado fora da cadeia confiável, é inválida")
    void rejectsUntrustedSigner() throws Exception {
        KeyPair keyPair = rsaKeyPair();
        SigningCredential untrusted = new SigningCredential(keyPair.getPrivate(), List.of(certificate(keyPair, "Signatário desconhecido")));

        VerificationResult result = verifier.verify(signer.sign(document, untrusted));

        assertThat(result.integrityValid()).isTrue();
        assertThat(result.certificateTrusted()).isFalse();
        assertThat(result.valid()).isFalse();
        assertThat(result.signerName()).isEqualTo("Signatário desconhecido");
        assertThat(result.certificationPath()).isEmpty();
    }

    @Test
    @DisplayName("Rejeita assinatura cuja data declarada está fora do período de validade do certificado")
    void rejectsSignatureOutsideCertificateValidity() throws Exception {
        KeyPair keyPair = rsaKeyPair();
        Instant future = NOW.plus(Duration.ofDays(10));
        SigningCredential notYetValid = new SigningCredential(keyPair.getPrivate(),
                List.of(selfSignedCertificate(keyPair, "Ainda não válido", future, future.plus(Duration.ofDays(365)))));

        VerificationResult result = verifier.verify(signer.sign(document, notYetValid));

        assertThat(result.integrityValid()).isFalse();
        assertThat(result.certificateTrusted()).isFalse();
        assertThat(result.failureReasons()).anyMatch(reason -> reason.contains("não estava válido"));
    }

    @Test
    @DisplayName("Assinatura sem o certificado do signatário embutido é inválida")
    void rejectsSignatureWithoutCertificate() throws Exception {
        VerificationResult result = verifier.verify(cms(true, false, null, credential));

        assertThat(result.integrityValid()).isFalse();
        assertThat(result.certificateTrusted()).isFalse();
        assertThat(result.signerCertificate()).isNull();
        assertThat(result.signerName()).isNull();
        assertThat(result.documentHash()).isEqualTo(DOCUMENT_SHA_512);
        assertThat(result.failureReasons()).containsExactly("O certificado do signatário não foi encontrado na assinatura");
    }

    @Test
    @DisplayName("Verifica normalmente uma assinatura sem o atributo signingTime")
    void verifiesSignatureWithoutSigningTime() throws Exception {
        VerificationResult result = verifier.verify(cms(true, true, CmsVerifierTest::attributesWithoutSigningTime, credential));

        assertThat(result.signingTime()).isNull();
        assertThat(result.valid()).isTrue();
    }

    @Test
    @DisplayName("Avalia a confiança na data da verificação: com o certificado expirado, a assinatura deixa de ser válida")
    void evaluatesTrustAtVerificationTime() {
        byte[] signature = signer.sign(document, credential);
        CmsVerifier verifierIn2030 = verifierAt(Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC));

        VerificationResult result = verifierIn2030.verify(signature);

        // Íntegra e assinada dentro da validade, mas o certificado venceu em 2029 e não há carimbo do tempo
        assertThat(result.integrityValid()).isTrue();
        assertThat(result.signingTime()).isEqualTo(NOW);
        assertThat(result.certificateTrusted()).isFalse();
        assertThat(result.valid()).isFalse();
        assertThat(result.failureReasons()).anyMatch(reason -> reason.contains("período de validade"));
    }

    @Test
    @DisplayName("Rejeita com INVALID_SIGNATURE_FORMAT assinatura cujo certificado embutido tem a chave pública malformada")
    void rejectsEmbeddedCertificateWithMalformedPublicKey() throws Exception {
        byte[] signature = signer.sign(document, credential);
        // A chave RSA, dentro do certificado, começa com a tag SEQUENCE (0x30). Trocá-la por SET (0x31)
        // mantém a estrutura ASN.1 do certificado, mas torna a chave pública ilegível
        byte[] rsaPublicKey = SubjectPublicKeyInfo.getInstance(credential.certificate().getPublicKey().getEncoded()).getPublicKeyData().getBytes();
        signature[indexOf(signature, rsaPublicKey)] = 0x31;

        assertThatThrownBy(() -> verifier.verify(signature))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.INVALID_SIGNATURE_FORMAT);
    }

    @Test
    @DisplayName("Rejeita conteúdo que não é CMS com INVALID_SIGNATURE_FORMAT")
    void rejectsContentThatIsNotCms() {
        byte[] randomBytes = new byte[256];
        new Random(42).nextBytes(randomBytes);

        assertThatThrownBy(() -> verifier.verify(randomBytes))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.INVALID_SIGNATURE_FORMAT);
    }

    @Test
    @DisplayName("Rejeita estrutura ASN.1 válida que não é CMS (um certificado) com INVALID_SIGNATURE_FORMAT")
    void rejectsAsn1ThatIsNotCms() throws Exception {
        byte[] certificate = credential.certificate().getEncoded();

        assertThatThrownBy(() -> verifier.verify(certificate))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.INVALID_SIGNATURE_FORMAT);
    }

    @Test
    @DisplayName("Rejeita assinatura detached (sem o documento) com INVALID_SIGNATURE_FORMAT")
    void rejectsDetachedSignature() throws Exception {
        byte[] detached = cms(false, true, null, credential);

        assertThatThrownBy(() -> verifier.verify(detached))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.INVALID_SIGNATURE_FORMAT)
                .hasMessageContaining("detached");
    }

    @Test
    @DisplayName("Rejeita assinatura com mais de um signatário com INVALID_SIGNATURE_FORMAT")
    void rejectsMultipleSigners() throws Exception {
        byte[] twoSigners = cms(true, true, null, credential, credential);

        assertThatThrownBy(() -> verifier.verify(twoSigners))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.INVALID_SIGNATURE_FORMAT)
                .hasMessageContaining("exatamente um signatário");
    }

    /**
     * Gera, diretamente com o BouncyCastle, variações de assinatura que o {@link CmsSigner} não produz.
     *
     * @param signedAttributes gerador dos atributos assinados; {@code null} usa o padrão do BouncyCastle
     */
    private static byte[] cms(boolean encapsulate, boolean includeCertificates, CMSAttributeTableGenerator signedAttributes,
                              SigningCredential... signers) throws Exception {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        var digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(PROVIDER).build();
        for (SigningCredential signerCredential : signers) {
            var signerInfoBuilder = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider);
            if (signedAttributes != null) {
                signerInfoBuilder.setSignedAttributeGenerator(signedAttributes);
            }
            var contentSigner = new JcaContentSignerBuilder(CmsSigner.SIGNATURE_ALGORITHM).setProvider(PROVIDER).build(signerCredential.privateKey());
            generator.addSignerInfoGenerator(signerInfoBuilder.build(contentSigner, signerCredential.certificate()));
        }
        if (includeCertificates) {
            generator.addCertificates(new JcaCertStore(signers[0].certificateChain()));
        }
        return generator.generate(new CMSProcessableByteArray(document), encapsulate).getEncoded();
    }

    /** Atributos assinados obrigatórios (contentType e messageDigest), sem o signingTime. */
    private static AttributeTable attributesWithoutSigningTime(Map<?, ?> parameters) {
        ASN1EncodableVector attributes = new ASN1EncodableVector();
        attributes.add(new Attribute(CMSAttributes.contentType, new DERSet((ASN1ObjectIdentifier) parameters.get(CMSAttributeTableGenerator.CONTENT_TYPE))));
        attributes.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString((byte[]) parameters.get(CMSAttributeTableGenerator.DIGEST)))));
        return new AttributeTable(attributes);
    }

    private static CmsVerifier verifierAt(Clock clock) {
        return new CmsVerifier(new DigestService(PROVIDER), CertificateTrustValidator.fromDirectory(TRUST_CHAIN_DIRECTORY, PROVIDER), PROVIDER, clock);
    }

    /** Certificado autoassinado válido na data fixa dos testes. */
    private static X509Certificate certificate(KeyPair keyPair, String commonName) throws Exception {
        return selfSignedCertificate(keyPair, commonName, NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(365)));
    }

    private static int indexOf(byte[] data, byte[] fragment) {
        outer:
        for (int i = 0; i <= data.length - fragment.length; i++) {
            for (int j = 0; j < fragment.length; j++) {
                if (data[i + j] != fragment[j]) {
                    continue outer;
                }
            }
            return i;
        }
        throw new IllegalArgumentException("Fragmento não encontrado");
    }
}
