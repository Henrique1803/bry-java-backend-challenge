package br.com.bry.challenge.crypto;

import java.io.IOException;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
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
 * <p>Além do hash do conteúdo, a assinatura inclui os atributos assinados padrão do BouncyCastle
 * ({@code contentType}, {@code messageDigest}, {@code signingTime} e
 * {@code cmsAlgorithmProtection}) e a cadeia de certificados do signatário.
 */
@Component
public class CmsSigner {

    public static final String SIGNATURE_ALGORITHM = "SHA512withRSA";

    private final Provider provider;

    public CmsSigner(Provider provider) {
        this.provider = Objects.requireNonNull(provider, "provider");
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
                    .build(contentSigner, credential.certificate()));
            generator.addCertificates(new JcaCertStore(credential.certificateChain()));

            // encapsulate = true: assinatura attached, com o documento dentro da estrutura CMS
            CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(content), true);
            return signedData.getEncoded(ASN1Encoding.DER);
        } catch (OperatorCreationException | CMSException | CertificateEncodingException | IOException e) {
            throw new CryptoException(CryptoErrorCode.SIGNATURE_FAILED, "Não foi possível gerar a assinatura CMS", e);
        }
    }
}
