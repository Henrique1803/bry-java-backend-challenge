package br.com.bry.challenge.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifica se um certificado é confiável, construindo e validando (PKIX) um caminho de certificação
 * até uma das ACs raiz da cadeia confiável.
 *
 * <p>Os certificados autoassinados da cadeia são usados como âncoras de confiança; os demais, como
 * ACs intermediárias. A verificação de revogação (LCR/OCSP) está desabilitada, pois exigiria acesso
 * à rede para obter as listas publicadas pelas ACs.
 */
public class CertificateTrustValidator {

    private static final Logger log = LoggerFactory.getLogger(CertificateTrustValidator.class);

    private static final String CERTIFICATE_FILES = "*.{cer,crt,pem}";

    private final Set<TrustAnchor> trustAnchors;
    private final List<X509Certificate> intermediateCertificates;
    private final Provider provider;

    public CertificateTrustValidator(Collection<X509Certificate> trustedCertificates, Provider provider) {
        this.provider = Objects.requireNonNull(provider, "provider");
        Set<TrustAnchor> anchors = new HashSet<>();
        List<X509Certificate> intermediates = new ArrayList<>();
        for (X509Certificate certificate : trustedCertificates) {
            if (isSelfSigned(certificate)) {
                anchors.add(new TrustAnchor(certificate, null));
            } else {
                intermediates.add(certificate);
            }
        }
        if (anchors.isEmpty()) {
            throw new IllegalArgumentException("A cadeia confiável deve conter ao menos um certificado raiz (autoassinado)");
        }
        this.trustAnchors = Set.copyOf(anchors);
        this.intermediateCertificates = List.copyOf(intermediates);
    }

    /**
     * Cria o validador a partir dos certificados (DER ou PEM) de um diretório. Falhas impedem a
     * criação, pois sem a cadeia confiável nenhuma assinatura poderia ser validada.
     */
    public static CertificateTrustValidator fromDirectory(Path directory, Provider provider) {
        List<X509Certificate> certificates = new ArrayList<>();
        try (DirectoryStream<Path> files = Files.newDirectoryStream(directory, CERTIFICATE_FILES)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (Path file : files) {
                try (InputStream input = Files.newInputStream(file)) {
                    certificates.add((X509Certificate) factory.generateCertificate(input));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao ler a cadeia confiável em " + directory, e);
        } catch (CertificateException e) {
            throw new IllegalStateException("Certificado inválido na cadeia confiável em " + directory, e);
        }
        return new CertificateTrustValidator(certificates, provider);
    }

    /**
     * Valida o certificado na data informada.
     *
     * @param certificate            certificado a ser validado
     * @param additionalCertificates certificados extras que podem compor o caminho (por exemplo, os
     *                               embutidos na assinatura); a confiança continua dependendo das raízes
     * @param validationTime         data de referência da validação
     */
    public TrustResult validate(X509Certificate certificate, Collection<X509Certificate> additionalCertificates, Instant validationTime) {
        Date date = Date.from(validationTime);
        try {
            certificate.checkValidity(date);
        } catch (CertificateException e) {
            return TrustResult.untrusted("O certificado não estava dentro do período de validade em " + validationTime);
        }

        try {
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(certificate);

            List<X509Certificate> candidates = new ArrayList<>(intermediateCertificates);
            candidates.addAll(additionalCertificates);
            candidates.add(certificate);

            PKIXBuilderParameters parameters = new PKIXBuilderParameters(trustAnchors, target);
            parameters.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(candidates)));
            parameters.setDate(date);
            parameters.setRevocationEnabled(false);

            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX", provider).build(parameters);

            // O caminho retornado não inclui a âncora de confiança, que é acrescentada ao final
            List<X509Certificate> path = new ArrayList<>();
            result.getCertPath().getCertificates().forEach(c -> path.add((X509Certificate) c));
            path.add(result.getTrustAnchor().getTrustedCert());
            return TrustResult.trusted(path);
        } catch (GeneralSecurityException e) {
            log.debug("Caminho de certificação não validado para {}", certificate.getSubjectX500Principal(), e);
            return TrustResult.untrusted("Não foi possível formar um caminho de certificação válido até uma AC raiz confiável");
        }
    }

    private static boolean isSelfSigned(X509Certificate certificate) {
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Resultado da validação de confiança.
     *
     * @param trusted           se foi possível validar um caminho até uma AC raiz confiável
     * @param certificationPath caminho do certificado até a raiz (vazio quando não confiável)
     * @param failureReason     motivo da falha (nulo quando confiável)
     */
    public record TrustResult(boolean trusted, List<X509Certificate> certificationPath, String failureReason) {

        public TrustResult {
            certificationPath = List.copyOf(certificationPath);
        }

        static TrustResult trusted(List<X509Certificate> certificationPath) {
            return new TrustResult(true, certificationPath, null);
        }

        static TrustResult untrusted(String failureReason) {
            return new TrustResult(false, List.of(), failureReason);
        }
    }
}
