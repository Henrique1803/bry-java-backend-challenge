package br.com.bry.challenge.crypto;

/**
 * Códigos estáveis que identificam o motivo de uma {@link CryptoException}.
 * A camada de API usa esses códigos para escolher o status HTTP e informá-los ao cliente.
 */
public enum CryptoErrorCode {

    /** O algoritmo solicitado não é suportado pelo provider criptográfico. */
    UNSUPPORTED_ALGORITHM,

    /** O arquivo PKCS12 está vazio, corrompido ou não está no formato esperado. */
    INVALID_PKCS12,

    /** A senha informada não abre o PKCS12 ou não dá acesso à chave privada. */
    INVALID_PASSWORD,

    /** O PKCS12 não contém a chave privada esperada: não há chave, o alias não corresponde a uma chave ou há várias e nenhum alias foi informado. */
    PRIVATE_KEY_NOT_FOUND,

    /** A chave privada não é do tipo exigido (RSA). */
    UNSUPPORTED_KEY,

    /** Falha ao gerar a assinatura CMS. */
    SIGNATURE_FAILED,

    /** O conteúdo recebido não é uma assinatura CMS attached com um único signatário. */
    INVALID_SIGNATURE_FORMAT
}
