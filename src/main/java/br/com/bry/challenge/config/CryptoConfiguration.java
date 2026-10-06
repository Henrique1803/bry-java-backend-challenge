package br.com.bry.challenge.config;

import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
}
