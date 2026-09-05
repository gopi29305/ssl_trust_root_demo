package com.example.ssltrust.upstream;

import com.example.ssltrust.pki.DemoCertificates;
import com.example.ssltrust.tls.TlsSupport;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;

/**
 * Boots the two upstreams that make the experiment possible.
 *
 * <ul>
 *   <li>{@code fullChain} — keystore chain {@code [leaf, intermediate]}. This is
 *       the correct server configuration (equivalent to nginx {@code fullchain.pem}
 *       or a Java keystore built with {@code -certchain}).</li>
 *   <li>{@code leafOnly} — keystore chain {@code [leaf]}. This is the classic
 *       misconfiguration: the server presents its own certificate and assumes
 *       the client already has the intermediate. Browsers often still work;
 *       Java usually does not.</li>
 * </ul>
 *
 * <p>Both servers use the same leaf key pair. The only difference is which
 * certificates are attached to that key in the keystore.
 */
@Component
public class UpstreamServerPair implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(UpstreamServerPair.class);

    private final UpstreamHttpsServer fullChain;
    private final UpstreamHttpsServer leafOnly;

    public UpstreamServerPair(DemoCertificates certificates) throws Exception {
        X509Certificate leaf = certificates.leafCertificate();
        X509Certificate intermediate = certificates.intermediateCertificate();

        this.fullChain = UpstreamHttpsServer.start(
                "full-chain",
                TlsSupport.serverSslContext(
                        TlsSupport.serverKeyStore(certificates.leafPrivateKey(), leaf, intermediate)
                ),
                """
                {"server":"full-chain","message":"Handshake reached an upstream that sent leaf + intermediate."}
                """
        );

        this.leafOnly = UpstreamHttpsServer.start(
                "leaf-only",
                TlsSupport.serverSslContext(
                        TlsSupport.serverKeyStore(certificates.leafPrivateKey(), leaf)
                ),
                """
                {"server":"leaf-only","message":"Handshake reached an upstream that sent the leaf only."}
                """
        );

        log.info("Full-chain upstream listening on {}", fullChain.pingUrl());
        log.info("Leaf-only upstream listening on {}", leafOnly.pingUrl());
    }

    public UpstreamHttpsServer fullChain() {
        return fullChain;
    }

    public UpstreamHttpsServer leafOnly() {
        return leafOnly;
    }

    @PreDestroy
    @Override
    public void close() {
        fullChain.close();
        leafOnly.close();
    }
}
