package br.com.bry.challenge.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import br.com.bry.challenge.crypto.CryptoErrorCode;
import br.com.bry.challenge.crypto.CryptoException;

/**
 * Converte as exceções da API em respostas no formato Problem Details (RFC 9457). Além dos campos
 * padrão, toda resposta de erro inclui {@code code}, um identificador estável do motivo do erro.
 */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    static final String CODE = "code";
    static final String MISSING_FIELD = "MISSING_FIELD";
    static final String EMPTY_FILE = "EMPTY_FILE";
    static final String FILE_TOO_LARGE = "FILE_TOO_LARGE";
    static final String UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE";
    static final String INTERNAL_ERROR = "INTERNAL_ERROR";

    @ExceptionHandler(CryptoException.class)
    public ResponseEntity<ProblemDetail> handleCryptoException(CryptoException e) {
        HttpStatus status = statusOf(e.getErrorCode());
        if (status.is5xxServerError()) {
            log.error("Falha na operação criptográfica ({})", e.getErrorCode(), e);
        } else {
            log.warn("Requisição rejeitada ({}): {}", e.getErrorCode(), e.getMessage());
        }
        return ResponseEntity.status(status).body(problem(status, e.getErrorCode().name(), e.getMessage()));
    }

    /** Erros não previstos: o detalhe técnico fica apenas no log, sem ser exposto ao cliente. */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleUnexpected(Exception e) {
        log.error("Erro inesperado ao processar a requisição", e);
        return ResponseEntity.internalServerError()
                .body(problem(HttpStatus.INTERNAL_SERVER_ERROR, INTERNAL_ERROR, "Erro interno ao processar a requisição"));
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestPart(MissingServletRequestPartException e, HttpHeaders headers,
                                                                     HttpStatusCode status, WebRequest request) {
        return ResponseEntity.badRequest()
                .body(problem(HttpStatus.BAD_REQUEST, MISSING_FIELD, "O campo '" + e.getRequestPartName() + "' é obrigatório"));
    }

    @Override
    protected ResponseEntity<Object> handleMaxUploadSizeExceededException(MaxUploadSizeExceededException e, HttpHeaders headers,
                                                                          HttpStatusCode status, WebRequest request) {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(problem(HttpStatus.PAYLOAD_TOO_LARGE, FILE_TOO_LARGE, "O arquivo enviado excede o tamanho máximo permitido"));
    }

    @Override
    protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(HttpMediaTypeNotSupportedException e, HttpHeaders headers,
                                                                     HttpStatusCode status, WebRequest request) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(problem(HttpStatus.UNSUPPORTED_MEDIA_TYPE, UNSUPPORTED_MEDIA_TYPE, "A requisição deve ser enviada como multipart/form-data"));
    }

    /** Erros causados pelos dados enviados resultam em 400; falhas na geração da assinatura, em 500. */
    static HttpStatus statusOf(CryptoErrorCode code) {
        return switch (code) {
            case INVALID_PKCS12, INVALID_PASSWORD, PRIVATE_KEY_NOT_FOUND, UNSUPPORTED_KEY,
                 UNSUPPORTED_ALGORITHM, INVALID_SIGNATURE_FORMAT -> HttpStatus.BAD_REQUEST;
            case SIGNATURE_FAILED -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
    }

    static ProblemDetail problem(HttpStatus status, String code, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setProperty(CODE, code);
        return problem;
    }
}
