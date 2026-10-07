package br.com.bry.challenge.crypto;

import java.io.IOException;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.time.Clock;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.stereotype.Component;

/**
 * Gera assinaturas digitais no padrão CMS (RFC 5652), do tipo attached, com SHA-512 e RSA.
 *
 * <p>Além do hash do conteúdo, a assinatura inclui os atributos assinados {@code signingTime}
 * (obtido do relógio da aplicação), {@code contentType}, {@code messageDigest} e
 * {@code cmsAlgorithmProtection} (adicionados pelo BouncyCastle) e a cadeia de certificados do
 * signatário.
 */
@Component
public class CmsSigner {

    public static final String SIGNATURE_ALGORITHM = "SHA512withRSA";

    private final Provider provider;
    private final Clock clock;

    public CmsSigner(Provider provider, Clock clock) {
        this.provider = Objects.requireNonNull(provider, "provider");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Assina o conteúdo e retorna a estrutura CMS codificada em DER (formato de um arquivo .p7s).
     */
    public byte[] sign(byte[] content, SigningCredential credential) {
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(credential, "credential");

        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(provider).build(credential.privateKey());
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(provider).build();

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
                    .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(signingTimeAttribute()))
                    .build(contentSigner, credential.certificate()));
            generator.addCertificates(new JcaCertStore(credential.certificateChain()));

            // encapsulate = true: assinatura attached, com o documento dentro da estrutura CMS
            CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(content), true);
            return signedData.getEncoded(ASN1Encoding.DER);
        } catch (OperatorCreationException | CMSException | CertificateEncodingException | IOException e) {
            throw new CryptoException(CryptoErrorCode.SIGNATURE_FAILED, "Não foi possível gerar a assinatura CMS", e);
        }
    }

    private AttributeTable signingTimeAttribute() {
        Time signingTime = new Time(Date.from(clock.instant()));
        return new AttributeTable(new Attribute(CMSAttributes.signingTime, new DERSet(signingTime)));
    }
}
