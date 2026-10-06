package br.com.bry.challenge.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.springframework.stereotype.Component;

/**
 * Extrai a chave privada RSA e o certificado do signatário de um arquivo PKCS12 (.pfx/.p12),
 * usando a classe {@link KeyStore} do Java. Os streams recebidos não são fechados, pois pertencem
 * a quem chamou.
 */
@Component
public class Pkcs12CredentialLoader {

    private static final String KEYSTORE_TYPE = "PKCS12";

    /**
     * Carrega a credencial de um PKCS12 que contém exatamente uma chave privada.
     *
     * @param pkcs12   conteúdo do arquivo PKCS12
     * @param password senha do arquivo (também usada para a chave privada)
     */
    public SigningCredential load(InputStream pkcs12, char[] password) {
        return loadCredential(pkcs12, password, null);
    }

    /**
     * Carrega a credencial da chave privada identificada pelo alias.
     *
     * @param pkcs12   conteúdo do arquivo PKCS12
     * @param password senha do arquivo (também usada para a chave privada)
     * @param alias    alias exato da chave privada no arquivo
     */
    public SigningCredential load(InputStream pkcs12, char[] password, String alias) {
        Objects.requireNonNull(alias, "alias");
        return loadCredential(pkcs12, password, alias);
    }

    private SigningCredential loadCredential(InputStream pkcs12, char[] password, String alias) {
        Objects.requireNonNull(pkcs12, "pkcs12");
        Objects.requireNonNull(password, "password");

        KeyStore keyStore = openKeyStore(pkcs12, password);
        try {
            String keyAlias = alias == null ? singlePrivateKeyAlias(keyStore) : requirePrivateKeyAlias(keyStore, alias);
            return readCredential(keyStore, keyAlias, password);
        } catch (UnrecoverableKeyException e) {
            throw new CryptoException(CryptoErrorCode.INVALID_PASSWORD, "A senha informada não dá acesso à chave privada do PKCS12", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(CryptoErrorCode.INVALID_PKCS12, "Não foi possível ler a chave privada do PKCS12", e);
        }
    }

    private KeyStore openKeyStore(InputStream pkcs12, char[] password) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(pkcs12, password);
            return keyStore;
        } catch (IOException | GeneralSecurityException e) {
            // O KeyStore sinaliza senha incorreta com uma IOException causada por UnrecoverableKeyException
            if (e.getCause() instanceof UnrecoverableKeyException) {
                throw new CryptoException(CryptoErrorCode.INVALID_PASSWORD, "Senha do PKCS12 incorreta", e);
            }
            throw new CryptoException(CryptoErrorCode.INVALID_PKCS12, "Arquivo PKCS12 inválido ou corrompido", e);
        }
    }

    /** Exige que o arquivo tenha uma única chave privada, sem escolher entre várias ao acaso. */
    private String singlePrivateKeyAlias(KeyStore keyStore) throws GeneralSecurityException {
        List<String> keyAliases = privateKeyAliases(keyStore);
        if (keyAliases.isEmpty()) {
            throw new CryptoException(CryptoErrorCode.PRIVATE_KEY_NOT_FOUND, "O PKCS12 não contém chave privada");
        }
        if (keyAliases.size() > 1) {
            throw new CryptoException(CryptoErrorCode.PRIVATE_KEY_NOT_FOUND,
                    "O PKCS12 contém " + keyAliases.size() + " chaves privadas, mas deve conter apenas uma");
        }
        return keyAliases.get(0);
    }

    /** Exige que o alias identifique uma chave privada; a mensagem de erro lista os aliases disponíveis. */
    private String requirePrivateKeyAlias(KeyStore keyStore, String alias) throws GeneralSecurityException {
        if (keyStore.isKeyEntry(alias)) {
            return alias;
        }
        throw new CryptoException(CryptoErrorCode.PRIVATE_KEY_NOT_FOUND,
                "Alias '" + alias + "' não corresponde a uma chave privada do PKCS12. Chaves privadas disponíveis: " + privateKeyAliases(keyStore));
    }

    private List<String> privateKeyAliases(KeyStore keyStore) throws GeneralSecurityException {
        List<String> keyAliases = new ArrayList<>();
        for (String alias : Collections.list(keyStore.aliases())) {
            if (keyStore.isKeyEntry(alias)) {
                keyAliases.add(alias);
            }
        }
        return keyAliases;
    }

    private SigningCredential readCredential(KeyStore keyStore, String alias, char[] password) throws GeneralSecurityException {
        Key key = keyStore.getKey(alias, password);
        if (!(key instanceof RSAPrivateKey privateKey)) {
            throw new CryptoException(CryptoErrorCode.UNSUPPORTED_KEY, "A chave privada do PKCS12 deve ser RSA, mas é " + key.getAlgorithm());
        }

        Certificate[] chain = keyStore.getCertificateChain(alias);
        if (chain == null || chain.length == 0) {
            throw new CryptoException(CryptoErrorCode.INVALID_PKCS12, "O PKCS12 não contém o certificado da chave privada");
        }
        List<X509Certificate> certificates = Arrays.stream(chain).map(X509Certificate.class::cast).toList();
        return new SigningCredential(privateKey, certificates);
    }
}
