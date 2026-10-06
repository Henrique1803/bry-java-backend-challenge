package br.com.bry.challenge.crypto;

/**
 * Exceção de domínio para falhas nas operações criptográficas.
 * O motivo é identificado por um {@link CryptoErrorCode}, evitando uma subclasse por tipo de erro.
 */
public class CryptoException extends RuntimeException {

    private final CryptoErrorCode errorCode;

    public CryptoException(CryptoErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public CryptoErrorCode getErrorCode() {
        return errorCode;
    }
}
