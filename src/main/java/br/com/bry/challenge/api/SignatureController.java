package br.com.bry.challenge.api;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import br.com.bry.challenge.crypto.CmsSigner;
import br.com.bry.challenge.crypto.CmsVerifier;
import br.com.bry.challenge.crypto.Pkcs12CredentialLoader;
import br.com.bry.challenge.crypto.SigningCredential;

/**
 * Endpoints de assinatura e verificação de assinaturas CMS attached.
 */
@RestController
public class SignatureController {

    private static final Logger log = LoggerFactory.getLogger(SignatureController.class);

    private final Pkcs12CredentialLoader credentialLoader;
    private final CmsSigner cmsSigner;
    private final CmsVerifier cmsVerifier;

    public SignatureController(Pkcs12CredentialLoader credentialLoader, CmsSigner cmsSigner, CmsVerifier cmsVerifier) {
        this.credentialLoader = credentialLoader;
        this.cmsSigner = cmsSigner;
        this.cmsVerifier = cmsVerifier;
    }

    /**
     * Assina o arquivo com a chave privada do PKCS12 e retorna a assinatura CMS attached em Base64.
     */
    @PostMapping(path = "/signature/", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public String sign(@RequestPart("file") MultipartFile file,
                       @RequestPart("pkcs12") MultipartFile pkcs12,
                       @RequestPart("password") String password) throws IOException {
        if (file.isEmpty()) {
            throw new ErrorResponseException(HttpStatus.BAD_REQUEST,
                    ApiExceptionHandler.problem(HttpStatus.BAD_REQUEST, ApiExceptionHandler.EMPTY_FILE, "O arquivo a ser assinado está vazio"), null);
        }

        char[] pkcs12Password = password.toCharArray();
        try (InputStream pkcs12Input = pkcs12.getInputStream()) {
            SigningCredential credential = credentialLoader.load(pkcs12Input, pkcs12Password);
            byte[] signature = cmsSigner.sign(file.getBytes(), credential);
            log.info("Assinatura gerada: documento de {} bytes, assinatura de {} bytes", file.getSize(), signature.length);
            return Base64.getEncoder().encodeToString(signature);
        } finally {
            // Remove a senha da memória assim que ela deixa de ser necessária
            Arrays.fill(pkcs12Password, '\0');
        }
    }

    /**
     * Verifica uma assinatura CMS attached (em Base64 ou DER) e retorna o status e as informações da assinatura.
     */
    @PostMapping(path = "/verify/", consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public VerifyResponse verify(@RequestPart("signature") MultipartFile signature) throws IOException {
        VerifyResponse response = VerifyResponse.from(cmsVerifier.verify(signature.getBytes()));
        log.info("Assinatura verificada: status {}", response.status());
        return response;
    }
}
