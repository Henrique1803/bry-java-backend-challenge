package br.com.bry.challenge.crypto;

/**
 * Códigos estáveis que identificam o motivo de uma {@link CryptoException}.
 * A camada de API usa esses códigos para escolher o status HTTP e informá-los ao cliente.
 */
public enum CryptoErrorCode {

    /** O algoritmo solicitado não é suportado pelo provider criptográfico. */
    UNSUPPORTED_ALGORITHM
}
