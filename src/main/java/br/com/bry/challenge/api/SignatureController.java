package br.com.bry.challenge.api;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Base64;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
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
                       @RequestParam("password") String password) throws IOException {
        char[] pkcs12Password = password.toCharArray();
        try (InputStream pkcs12Input = pkcs12.getInputStream()) {
            SigningCredential credential = credentialLoader.load(pkcs12Input, pkcs12Password);
            return Base64.getEncoder().encodeToString(cmsSigner.sign(file.getBytes(), credential));
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
        return VerifyResponse.from(cmsVerifier.verify(signature.getBytes()));
    }
}
