package br.com.bry.challenge.config;

import java.security.Provider;
import java.time.Clock;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import br.com.bry.challenge.crypto.CertificateTrustValidator;

/**
 * Configuração da infraestrutura criptográfica.
 *
 * <p>Uma única instância do provider BouncyCastle é compartilhada e injetada nos serviços, que a
 * usam explicitamente. Assim não é necessário registrá-la globalmente com
 * {@code Security.addProvider}, o que alteraria o estado de toda a JVM.
 */
@Configuration(proxyBeanMethods = false)
public class CryptoConfiguration {

    @Bean
    public Provider bouncyCastleProvider() {
        return new BouncyCastleProvider();
    }

    /** Relógio da aplicação, injetado para que as datas de assinatura e de validação sejam testáveis. */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * Cadeia de confiança carregada na inicialização. Se os certificados não puderem ser lidos,
     * a aplicação não sobe, pois o componente responsável pela validação de confiança não pode
     * ser inicializado corretamente.
     */
    @Bean
    public CertificateTrustValidator certificateTrustValidator(ChallengeProperties properties, Provider provider) {
        return CertificateTrustValidator.fromDirectory(properties.trustChainDirectory(), provider);
    }
}
