package com.example.ssltrust.pki;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * In-memory PKI used by the demo: a three-tier hierarchy.
 *
 * <pre>
 *   Demo Root CA                (self-signed trust anchor)
 *        │
 *        ▼
 *   Demo Intermediate CA        (signed by the root)
 *        │
 *        ▼
 *   localhost leaf              (signed by the intermediate; used as the HTTPS server cert)
 * </pre>
 *
 * <p>This is the same shape as a typical public CA (for example DigiCert / Let's Encrypt)
 * or a corporate private PKI. The Java client never needs the leaf or (normally) the
 * intermediate in its truststore — it needs the root, plus a complete chain from the server.
 */
public record DemoCertificates(
        X509Certificate rootCertificate,
        PrivateKey rootPrivateKey,
        X509Certificate intermediateCertificate,
        PrivateKey intermediatePrivateKey,
        X509Certificate leafCertificate,
        PrivateKey leafPrivateKey
) {

    public List<String> chainSubjectsRootToLeaf() {
        return List.of(
                subject(rootCertificate),
                subject(intermediateCertificate),
                subject(leafCertificate)
        );
    }

    public static String subject(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().getName();
    }

    public static String issuer(X509Certificate certificate) {
        return certificate.getIssuerX500Principal().getName();
    }
}
