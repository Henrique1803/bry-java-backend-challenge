package br.com.bry.challenge.api;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Sobe o servidor HTTP real, pois o limite de tamanho do multipart é aplicado pelo servidor (e não
 * pelo MockMvc). O limite é reduzido para 1 KB para não precisar enviar arquivos grandes.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.servlet.multipart.max-file-size=1KB",
        "spring.servlet.multipart.max-request-size=10KB"
})
class UploadLimitIntegrationTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    @DisplayName("Retorna 413 FILE_TOO_LARGE quando o arquivo excede o tamanho máximo de upload")
    void rejectsFileLargerThanLimit() {
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("signature", new ByteArrayResource(new byte[2048]) {
            @Override
            public String getFilename() {
                return "assinatura.p7s";
            }
        });
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        ResponseEntity<String> response = restTemplate.postForEntity("/verify/", new HttpEntity<>(body, headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
        assertThat(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)).isTrue();
        assertThat(response.getBody()).contains("\"code\":\"FILE_TOO_LARGE\"");
    }
}
