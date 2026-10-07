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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
import org.springframework.mock.web.MockPart;
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
        String base64 = sign(document, Files.readAllBytes(PKCS12), new String(pkcs12Password()))
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
        String base64 = sign(document, Files.readAllBytes(PKCS12), new String(pkcs12Password()))
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

    @Test
    @DisplayName("POST /signature/ retorna 400 INVALID_PASSWORD quando a senha do PKCS12 está incorreta")
    void rejectsWrongPassword() throws Exception {
        sign(document, Files.readAllBytes(PKCS12), "senha-errada")
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.code").value("INVALID_PASSWORD"))
                .andExpect(jsonPath("$.detail").value("Senha do PKCS12 incorreta"));
    }

    @Test
    @DisplayName("POST /signature/ retorna 400 INVALID_PKCS12 quando o arquivo enviado não é um PKCS12")
    void rejectsInvalidPkcs12() throws Exception {
        sign(document, "não é um PKCS12".getBytes(StandardCharsets.UTF_8), new String(pkcs12Password()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_PKCS12"));
    }

    @Test
    @DisplayName("POST /signature/ retorna 400 EMPTY_FILE quando o arquivo a ser assinado está vazio")
    void rejectsEmptyDocument() throws Exception {
        sign(new byte[0], Files.readAllBytes(PKCS12), new String(pkcs12Password()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("EMPTY_FILE"));
    }

    @Test
    @DisplayName("POST /signature/ retorna 400 MISSING_FIELD indicando o arquivo ausente")
    void rejectsMissingFile() throws Exception {
        mockMvc.perform(multipart("/signature/")
                        .file(new MockMultipartFile("pkcs12", "certificado.pfx", "application/x-pkcs12", Files.readAllBytes(PKCS12)))
                        .part(new MockPart("password", new String(pkcs12Password()).getBytes(StandardCharsets.UTF_8))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MISSING_FIELD"))
                .andExpect(jsonPath("$.detail").value("O campo 'file' é obrigatório"));
    }

    @Test
    @DisplayName("POST /signature/ retorna 400 MISSING_FIELD indicando a senha ausente")
    void rejectsMissingPassword() throws Exception {
        mockMvc.perform(multipart("/signature/")
                        .file(new MockMultipartFile("file", "doc.txt", MediaType.TEXT_PLAIN_VALUE, document))
                        .file(new MockMultipartFile("pkcs12", "certificado.pfx", "application/x-pkcs12", Files.readAllBytes(PKCS12))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MISSING_FIELD"))
                .andExpect(jsonPath("$.detail").value("O campo 'password' é obrigatório"));
    }

    @Test
    @DisplayName("POST /verify/ retorna 400 INVALID_SIGNATURE_FORMAT quando o arquivo não é uma assinatura CMS")
    void rejectsContentThatIsNotSignature() throws Exception {
        verify("não é uma assinatura".getBytes(StandardCharsets.UTF_8))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.code").value("INVALID_SIGNATURE_FORMAT"));
    }

    @Test
    @DisplayName("POST /verify/ retorna 400 MISSING_FIELD quando a assinatura não é enviada")
    void rejectsMissingSignature() throws Exception {
        mockMvc.perform(multipart("/verify/").file(new MockMultipartFile("outro", "x.txt", MediaType.TEXT_PLAIN_VALUE, document)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MISSING_FIELD"))
                .andExpect(jsonPath("$.detail").value("O campo 'signature' é obrigatório"));
    }

    @Test
    @DisplayName("POST /verify/ retorna 415 UNSUPPORTED_MEDIA_TYPE quando a requisição não é multipart/form-data")
    void rejectsRequestThatIsNotMultipart() throws Exception {
        mockMvc.perform(post("/verify/").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(jsonPath("$.code").value("UNSUPPORTED_MEDIA_TYPE"));
    }

    private ResultActions sign(byte[] file, byte[] pkcs12, String password) throws Exception {
        return mockMvc.perform(multipart("/signature/")
                .file(new MockMultipartFile("file", "doc.txt", MediaType.TEXT_PLAIN_VALUE, file))
                .file(new MockMultipartFile("pkcs12", "certificado.pfx", "application/x-pkcs12", pkcs12))
                .part(new MockPart("password", password.getBytes(StandardCharsets.UTF_8))));
    }

    private ResultActions verify(byte[] signatureFile) throws Exception {
        return mockMvc.perform(multipart("/verify/")
                .file(new MockMultipartFile("signature", "doc.txt.p7s", MediaType.APPLICATION_OCTET_STREAM_VALUE, signatureFile)));
    }
}
