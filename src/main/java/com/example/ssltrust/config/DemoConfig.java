package com.example.ssltrust.config;

import com.example.ssltrust.pki.DemoCertificates;
import com.example.ssltrust.pki.DemoPki;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DemoConfig {

    /**
     * One generated PKI is shared by the upstream servers and the outbound clients
     * so we know exactly which certificates are in play.
     */
    @Bean
    DemoCertificates demoCertificates() {
        return DemoPki.generate();
    }
}
