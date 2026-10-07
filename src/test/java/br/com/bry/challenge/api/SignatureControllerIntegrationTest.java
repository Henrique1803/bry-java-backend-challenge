package br.com.bry.challenge.api;

import static br.com.bry.challenge.support.ChallengeResources.DOCUMENT;
import static br.com.bry.challenge.support.ChallengeResources.DOCUMENT_SHA_512;
import static br.com.bry.challenge.support.ChallengeResources.PKCS12;
import static br.com.bry.challenge.support.ChallengeResources.pkcs12Password;
import static br.com.bry.challenge.support.ChallengeResources.signingCredential;
import static br.com.bry.challenge.support.TestCertificates.rsaKeyPair;
import static br.com.bry.challenge.support.TestCertificates.selfSignedCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.util.Base64;
import java.util.List;

import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import br.com.bry.challenge.crypto.CmsSigner;
import br.com.bry.challenge.crypto.SigningCredential;

@SpringBootTest
@AutoConfigureMockMvc
class SignatureControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CmsSigner cmsSigner;

    private byte[] document;
    private byte[] signature;

    @BeforeEach
    void setUp() throws Exception {
        document = Files.readAllBytes(DOCUMENT);
        signature = cmsSigner.sign(document, signingCredential());
    }

    @Test
    @DisplayName("POST /signature/ retorna no corpo a assinatura CMS attached em Base64")
    void signsDocument() throws Exception {
        String base64 = mockMvc.perform(multipart("/signature/")
                        .file(new MockMultipartFile("file", "doc.txt", MediaType.TEXT_PLAIN_VALUE, document))
                        .file(new MockMultipartFile("pkcs12", "certificado.pfx", "application/x-pkcs12", Files.readAllBytes(PKCS12)))
                        .param("password", new String(pkcs12Password())))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_PLAIN))
                .andReturn().getResponse().getContentAsString();

        CMSSignedData signedData = new CMSSignedData(Base64.getDecoder().decode(base64));
        assertThat((byte[]) signedData.getSignedContent().getContent()).isEqualTo(document);
    }

    @Test
    @DisplayName("POST /verify/ retorna VALIDO e as informações obrigatórias para assinatura em Base64")
    void verifiesBase64Signature() throws Exception {
        verify(Base64.getEncoder().encode(signature))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("VALIDO"))
                .andExpect(jsonPath("$.infos.signerName").value("HUB2 TESTES"))
                .andExpect(jsonPath("$.infos.signingTime").isNotEmpty())
                .andExpect(jsonPath("$.infos.documentHash").value(DOCUMENT_SHA_512))
                .andExpect(jsonPath("$.infos.digestAlgorithm").value("SHA-512"));
    }

    @Test
    @DisplayName("POST /verify/ retorna as informações adicionais da verificação")
    void returnsAdditionalVerificationDetails() throws Exception {
        verify(Base64.getEncoder().encode(signature))
                .andExpect(jsonPath("$.details.integrityValid").value(true))
                .andExpect(jsonPath("$.details.certificateTrusted").value(true))
                .andExpect(jsonPath("$.details.certificate.subject").value(startsWith("CN=HUB2 TESTES")))
                .andExpect(jsonPath("$.details.certificate.issuer").value(containsString("CN=AC BRy Servidor Seguro v3")))
                .andExpect(jsonPath("$.details.certificate.serialNumber").value("25F"))
                .andExpect(jsonPath("$.details.certificate.notAfter").value("2029-07-21T18:22:00Z"))
                .andExpect(jsonPath("$.details.certificationPath.length()").value(3))
                .andExpect(jsonPath("$.details.failureReasons").isEmpty());
    }

    @Test
    @DisplayName("POST /verify/ aceita Base64 com quebras de linha")
    void acceptsBase64WithLineBreaks() throws Exception {
        verify(Base64.getMimeEncoder().encode(signature))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VALIDO"));
    }

    @Test
    @DisplayName("POST /verify/ aceita também o arquivo .p7s binário (DER)")
    void acceptsDerSignature() throws Exception {
        verify(signature)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VALIDO"));
    }

    @Test
    @DisplayName("POST /verify/ valida a assinatura retornada por POST /signature/")
    void verifiesSignatureFromSignatureEndpoint() throws Exception {
        String base64 = mockMvc.perform(multipart("/signature/")
                        .file(new MockMultipartFile("file", "doc.txt", MediaType.TEXT_PLAIN_VALUE, document))
                        .file(new MockMultipartFile("pkcs12", "certificado.pfx", "application/x-pkcs12", Files.readAllBytes(PKCS12)))
                        .param("password", new String(pkcs12Password())))
                .andReturn().getResponse().getContentAsString();

        verify(base64.getBytes(StandardCharsets.US_ASCII))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VALIDO"));
    }

    @Test
    @DisplayName("POST /verify/ retorna INVALIDO com o motivo quando o documento foi alterado")
    void returnsInvalidForTamperedDocument() throws Exception {
        // Altera 1 byte do documento embutido na assinatura
        byte[] tampered = signature.clone();
        tampered[new String(tampered, StandardCharsets.ISO_8859_1).indexOf(new String(document, StandardCharsets.ISO_8859_1))] ^= 0x01;

        verify(Base64.getEncoder().encode(tampered))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("INVALIDO"))
                .andExpect(jsonPath("$.details.integrityValid").value(false))
                .andExpect(jsonPath("$.details.failureReasons[0]").value(containsString("documento foi alterado")));
    }

    @Test
    @DisplayName("POST /verify/ retorna INVALIDO quando o certificado do signatário não é confiável")
    void returnsInvalidForUntrustedSigner() throws Exception {
        KeyPair keyPair = rsaKeyPair();
        SigningCredential untrusted = new SigningCredential(keyPair.getPrivate(), List.of(selfSignedCertificate(keyPair, "Signatário desconhecido")));

        verify(Base64.getEncoder().encode(cmsSigner.sign(document, untrusted)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("INVALIDO"))
                .andExpect(jsonPath("$.infos.signerName").value("Signatário desconhecido"))
                .andExpect(jsonPath("$.details.integrityValid").value(true))
                .andExpect(jsonPath("$.details.certificateTrusted").value(false))
                .andExpect(jsonPath("$.details.certificationPath").isEmpty());
    }

    private ResultActions verify(byte[] signatureFile) throws Exception {
        return mockMvc.perform(multipart("/verify/")
                .file(new MockMultipartFile("signature", "doc.txt.p7s", MediaType.APPLICATION_OCTET_STREAM_VALUE, signatureFile)));
    }
}
