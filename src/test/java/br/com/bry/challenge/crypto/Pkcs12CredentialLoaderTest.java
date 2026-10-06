package br.com.bry.challenge.crypto;

import static br.com.bry.challenge.support.ChallengeResources.PKCS12;
import static br.com.bry.challenge.support.ChallengeResources.PKCS12_ALIAS;
import static br.com.bry.challenge.support.ChallengeResources.pkcs12Password;
import static br.com.bry.challenge.support.TestCertificates.ecKeyPair;
import static br.com.bry.challenge.support.TestCertificates.pkcs12;
import static br.com.bry.challenge.support.TestCertificates.rsaKeyPair;
import static br.com.bry.challenge.support.TestCertificates.selfSignedCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.interfaces.RSAPrivateKey;
import java.util.Random;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class Pkcs12CredentialLoaderTest {

    /** Senha dos PKCS12 gerados em memória pelos testes. */
    private static final char[] PASSWORD = "senha-de-teste".toCharArray();

    private final Pkcs12CredentialLoader loader = new Pkcs12CredentialLoader();

    @Test
    @DisplayName("Carrega a credencial do PKCS12 do desafio pelo alias")
    void loadsChallengeCredentialByAlias() throws Exception {
        SigningCredential credential;
        try (InputStream input = Files.newInputStream(PKCS12)) {
            credential = loader.load(input, pkcs12Password(), PKCS12_ALIAS);
        }

        assertChallengeCredential(credential);
    }

    @Test
    @DisplayName("Carrega a credencial do PKCS12 do desafio sem alias, pois o arquivo tem uma única chave")
    void loadsChallengeCredentialWithoutAlias() throws Exception {
        SigningCredential credential;
        try (InputStream input = Files.newInputStream(PKCS12)) {
            credential = loader.load(input, pkcs12Password());
        }

        assertChallengeCredential(credential);
    }

    @Test
    @DisplayName("Seleciona a chave correspondente ao alias quando o arquivo tem várias chaves")
    void selectsKeyByAliasAmongSeveral() throws Exception {
        byte[] pkcs12 = pkcs12()
                .withKey("primeira", rsaKeyPair(), PASSWORD)
                .withKey("segunda", rsaKeyPair(), PASSWORD)
                .build(PASSWORD);

        SigningCredential credential = loader.load(new ByteArrayInputStream(pkcs12), PASSWORD, "segunda");

        assertThat(credential.certificate().getSubjectX500Principal().getName()).isEqualTo("CN=segunda");
    }

    @Test
    @DisplayName("Rejeita alias inexistente, listando as chaves privadas disponíveis")
    void rejectsUnknownAlias() throws Exception {
        byte[] pkcs12 = pkcs12()
                .withKey("primeira", rsaKeyPair(), PASSWORD)
                .withKey("segunda", rsaKeyPair(), PASSWORD)
                .build(PASSWORD);

        assertThatThrownBy(() -> loader.load(new ByteArrayInputStream(pkcs12), PASSWORD, "terceira"))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.PRIVATE_KEY_NOT_FOUND)
                .hasMessageContaining("terceira")
                .hasMessageContaining("primeira")
                .hasMessageContaining("segunda");
    }

    @Test
    @DisplayName("Rejeita alias que existe mas aponta para um certificado, não para uma chave privada")
    void rejectsAliasOfCertificateEntry() throws Exception {
        byte[] pkcs12 = pkcs12()
                .withKey("chave", rsaKeyPair(), PASSWORD)
                .withCertificate("certificado", selfSignedCertificate(rsaKeyPair(), "certificado"))
                .build(PASSWORD);

        assertThatThrownBy(() -> loader.load(new ByteArrayInputStream(pkcs12), PASSWORD, "certificado"))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.PRIVATE_KEY_NOT_FOUND);
    }

    @Test
    @DisplayName("Sem alias, rejeita arquivo com várias chaves em vez de escolher uma ao acaso")
    void rejectsSeveralKeysWithoutAlias() throws Exception {
        byte[] pkcs12 = pkcs12()
                .withKey("primeira", rsaKeyPair(), PASSWORD)
                .withKey("segunda", rsaKeyPair(), PASSWORD)
                .build(PASSWORD);

        assertThatThrownBy(() -> load(pkcs12, PASSWORD))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.PRIVATE_KEY_NOT_FOUND)
                .hasMessageContaining("2 chaves privadas");
    }

    @Test
    @DisplayName("Rejeita senha incorreta com INVALID_PASSWORD")
    void rejectsWrongPassword() throws Exception {
        byte[] pkcs12 = Files.readAllBytes(PKCS12);

        assertThatThrownBy(() -> load(pkcs12, "senha-errada".toCharArray()))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.INVALID_PASSWORD);
    }

    @Test
    @DisplayName("Rejeita com INVALID_PASSWORD quando a senha abre o arquivo mas não a chave privada")
    void rejectsPasswordThatDoesNotUnlockPrivateKey() throws Exception {
        byte[] pkcs12 = pkcs12()
                .withKey("chave", rsaKeyPair(), "outra-senha".toCharArray())
                .build(PASSWORD);

        assertThatThrownBy(() -> load(pkcs12, PASSWORD))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.INVALID_PASSWORD);
    }

    @Test
    @DisplayName("Rejeita conteúdo que não é PKCS12 com INVALID_PKCS12")
    void rejectsContentThatIsNotPkcs12() {
        byte[] randomBytes = new byte[512];
        new Random(42).nextBytes(randomBytes);

        assertThatThrownBy(() -> load(randomBytes, PASSWORD))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.INVALID_PKCS12);
    }

    @Test
    @DisplayName("Rejeita arquivo vazio com INVALID_PKCS12")
    void rejectsEmptyContent() {
        assertThatThrownBy(() -> load(new byte[0], PASSWORD))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.INVALID_PKCS12);
    }

    @Test
    @DisplayName("Rejeita PKCS12 sem chave privada com PRIVATE_KEY_NOT_FOUND")
    void rejectsPkcs12WithoutPrivateKey() throws Exception {
        byte[] pkcs12 = pkcs12()
                .withCertificate("certificado", selfSignedCertificate(rsaKeyPair(), "certificado"))
                .build(PASSWORD);

        assertThatThrownBy(() -> load(pkcs12, PASSWORD))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.PRIVATE_KEY_NOT_FOUND)
                .hasMessageContaining("não contém chave privada");
    }

    @Test
    @DisplayName("Rejeita chave que não é RSA com UNSUPPORTED_KEY")
    void rejectsNonRsaKey() throws Exception {
        byte[] pkcs12 = pkcs12().withKey("chave-ec", ecKeyPair(), PASSWORD).build(PASSWORD);

        assertThatThrownBy(() -> load(pkcs12, PASSWORD))
                .isInstanceOf(CryptoException.class)
                .hasFieldOrPropertyWithValue("errorCode", CryptoErrorCode.UNSUPPORTED_KEY)
                .hasMessageContaining("EC");
    }

    private SigningCredential load(byte[] pkcs12, char[] password) {
        return loader.load(new ByteArrayInputStream(pkcs12), password);
    }

    private static void assertChallengeCredential(SigningCredential credential) {
        assertThat(credential.privateKey()).isInstanceOf(RSAPrivateKey.class);
        assertThat(((RSAPrivateKey) credential.privateKey()).getModulus().bitLength()).isEqualTo(2048);
        assertThat(credential.certificate().getSubjectX500Principal().getName()).contains("CN=HUB2 TESTES");
        assertThat(credential.certificateChain()).hasSize(1);
    }
}
