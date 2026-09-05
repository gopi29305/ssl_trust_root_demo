package com.example.ssltrust.web;

import com.example.ssltrust.demo.HandshakeDemoService;
import com.example.ssltrust.demo.ScenarioResult;
import com.example.ssltrust.pki.DemoCertificates;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * HTTP façade over {@link HandshakeDemoService}.
 *
 * <p>This Spring Boot app is itself a plain HTTP REST API (port 8080). The TLS
 * experiment happens on the <em>outbound</em> calls it makes to the two local
 * HTTPS upstreams.
 */
@RestController
public class SslDemoController {

    private final HandshakeDemoService demoService;

    public SslDemoController(HandshakeDemoService demoService) {
        this.demoService = demoService;
    }

    @GetMapping("/")
    public Map<String, String> index() {
        Map<String, String> links = new LinkedHashMap<>();
        links.put("allScenarios", "/api/ssl-demo");
        links.put("fullChainSuccess", "/api/ssl-demo/full-chain");
        links.put("leafOnlyFailure", "/api/ssl-demo/leaf-only");
        links.put("workaroundTrustIntermediate", "/api/ssl-demo/workaround-intermediate");
        links.put("workaroundPinLeaf", "/api/ssl-demo/workaround-pin-leaf");
        links.put("pki", "/api/ssl-demo/pki");
        return links;
    }

    @GetMapping("/api/ssl-demo")
    public List<ScenarioResult> all() {
        return demoService.runAll();
    }

    @GetMapping("/api/ssl-demo/full-chain")
    public ScenarioResult fullChain() {
        return demoService.trustRootAndServerSendsFullChain();
    }

    @GetMapping("/api/ssl-demo/leaf-only")
    public ScenarioResult leafOnly() {
        return demoService.trustRootButServerOmitsIntermediate();
    }

    @GetMapping("/api/ssl-demo/workaround-intermediate")
    public ScenarioResult workaroundIntermediate() {
        return demoService.workaroundTrustIntermediateToo();
    }

    @GetMapping("/api/ssl-demo/workaround-pin-leaf")
    public ScenarioResult workaroundPinLeaf() {
        return demoService.workaroundPinTheLeaf();
    }

    @GetMapping("/api/ssl-demo/pki")
    public Map<String, Object> pki() {
        DemoCertificates certs = demoService.certificates();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("hierarchy", List.of("Demo Root CA", "Demo Intermediate CA", "localhost leaf"));
        body.put("root", describe(certs.rootCertificate()));
        body.put("intermediate", describe(certs.intermediateCertificate()));
        body.put("leaf", describe(certs.leafCertificate()));
        body.put("fullChainUpstream", demoService.upstreams().fullChain().pingUrl());
        body.put("leafOnlyUpstream", demoService.upstreams().leafOnly().pingUrl());
        body.put("note", "The client RestClient truststore contains the root only, unless a workaround scenario says otherwise.");
        return body;
    }

    private static Map<String, String> describe(java.security.cert.X509Certificate certificate) {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("subject", DemoCertificates.subject(certificate));
        map.put("issuer", DemoCertificates.issuer(certificate));
        map.put("serial", certificate.getSerialNumber().toString(16));
        map.put("notBefore", certificate.getNotBefore().toInstant().toString());
        map.put("notAfter", certificate.getNotAfter().toInstant().toString());
        return map;
    }
}
