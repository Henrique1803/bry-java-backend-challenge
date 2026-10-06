package br.com.bry.challenge.support;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Gera chaves, certificados e keystores PKCS#12 em memória para os testes, permitindo exercitar
 * cenários de erro sem manter arquivos binários adicionais no repositório.
 */
public final class TestCertificates {

    private TestCertificates() {
    }

    public static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static KeyPair ecKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        return generator.generateKeyPair();
    }

    /** Certificado autoassinado com {@code CN=<commonName>}, válido de ontem até daqui a um ano. */
    public static X509Certificate selfSignedCertificate(KeyPair keyPair, String commonName) throws Exception {
        X500Name name = new X500Name("CN=" + commonName);
        Instant now = Instant.now();
        String signatureAlgorithm = "EC".equals(keyPair.getPrivate().getAlgorithm())
                ? "SHA256withECDSA"
                : "SHA256withRSA";

        var builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(365))),
                name, keyPair.getPublic());
        var signer = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    public static Pkcs12Builder pkcs12() throws Exception {
        return new Pkcs12Builder();
    }

    /** Monta um PKCS12 entrada por entrada e o serializa com a senha informada. */
    public static final class Pkcs12Builder {

        private final KeyStore keyStore;

        private Pkcs12Builder() throws Exception {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
        }

        /** Adiciona uma chave privada com certificado autoassinado cujo CN é o próprio alias. */
        public Pkcs12Builder withKey(String alias, KeyPair keyPair, char[] keyPassword) throws Exception {
            X509Certificate certificate = selfSignedCertificate(keyPair, alias);
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyPassword, new Certificate[] {certificate});
            return this;
        }

        /** Adiciona apenas um certificado confiável, sem chave privada. */
        public Pkcs12Builder withCertificate(String alias, X509Certificate certificate) throws Exception {
            keyStore.setCertificateEntry(alias, certificate);
            return this;
        }

        public byte[] build(char[] password) throws Exception {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            keyStore.store(output, password);
            return output.toByteArray();
        }
    }
}
