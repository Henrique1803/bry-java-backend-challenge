package br.com.bry.challenge.api;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;

import br.com.bry.challenge.crypto.CryptoErrorCode;
import br.com.bry.challenge.crypto.CryptoException;

class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    @ParameterizedTest(name = "{0}")
    @EnumSource(value = CryptoErrorCode.class, names = "SIGNATURE_FAILED", mode = EnumSource.Mode.EXCLUDE)
    @DisplayName("Erros causados pelos dados enviados resultam em 400, com o código e a mensagem do erro")
    void mapsClientErrorsToBadRequest(CryptoErrorCode code) {
        ResponseEntity<ProblemDetail> response = handler.handleCryptoException(new CryptoException(code, "mensagem do erro"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().getDetail()).isEqualTo("mensagem do erro");
        assertThat(response.getBody().getProperties()).containsEntry("code", code.name());
    }

    @Test
    @DisplayName("Falha na geração da assinatura resulta em 500")
    void mapsSignatureFailureToInternalServerError() {
        ResponseEntity<ProblemDetail> response = handler.handleCryptoException(
                new CryptoException(CryptoErrorCode.SIGNATURE_FAILED, "Não foi possível gerar a assinatura CMS"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody().getProperties()).containsEntry("code", "SIGNATURE_FAILED");
    }

    @Test
    @DisplayName("Erro inesperado resulta em 500 genérico, sem expor detalhes internos")
    void hidesUnexpectedErrorDetails() {
        ResponseEntity<ProblemDetail> response = handler.handleUnexpected(new IllegalStateException("detalhe interno sensível"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody().getDetail()).isEqualTo("Erro interno ao processar a requisição");
        assertThat(response.getBody().getProperties()).containsEntry("code", "INTERNAL_ERROR");
    }
}
