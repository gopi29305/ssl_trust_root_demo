package com.example.ssltrust.demo;

import com.example.ssltrust.pki.DemoCertificates;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Prints a readable report of every handshake scenario as soon as the app is up.
 * Disable with {@code demo.run-on-startup=false}.
 */
@Component
@Order(1)
@ConditionalOnProperty(name = "demo.run-on-startup", havingValue = "true", matchIfMissing = true)
public class StartupDemoRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(StartupDemoRunner.class);
    private static final String RULE = "-".repeat(88);

    private final HandshakeDemoService demoService;

    public StartupDemoRunner(HandshakeDemoService demoService) {
        this.demoService = demoService;
    }

    @Override
    public void run(ApplicationArguments args) {
        DemoCertificates certs = demoService.certificates();
        log.info(RULE);
        log.info("SSL trust-root demo — generated PKI");
        log.info("  Root         subject={} issuer={}",
                DemoCertificates.subject(certs.rootCertificate()),
                DemoCertificates.issuer(certs.rootCertificate()));
        log.info("  Intermediate subject={} issuer={}",
                DemoCertificates.subject(certs.intermediateCertificate()),
                DemoCertificates.issuer(certs.intermediateCertificate()));
        log.info("  Leaf         subject={} issuer={}",
                DemoCertificates.subject(certs.leafCertificate()),
                DemoCertificates.issuer(certs.leafCertificate()));
        log.info("  Full-chain upstream: {}", demoService.upstreams().fullChain().pingUrl());
        log.info("  Leaf-only upstream:  {}", demoService.upstreams().leafOnly().pingUrl());
        log.info(RULE);

        for (ScenarioResult result : demoService.runAll()) {
            log.info("Scenario : {}", result.id());
            log.info("  {}", result.title());
            log.info("  client truststore     : {}", result.clientTruststore());
            log.info("  server presented chain: {}", result.serverPresentedChain());
            log.info("  PKIX path built       : {} ({})", result.pkixPathBuilt(), result.pkixDetail());
            log.info("  handshake succeeded   : {}", result.handshakeSucceeded());
            if (result.handshakeSucceeded()) {
                log.info("  HTTP body             : {}", result.httpBody());
            } else {
                log.info("  error                 : {}", result.error());
            }
            log.info("  why: {}", result.why());
            log.info(RULE);
        }

        log.info("Call GET http://127.0.0.1:8080/api/ssl-demo for the same report as JSON.");
    }
}
