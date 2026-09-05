package com.example.ssltrust.tls;

import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Runs the same PKIX path-building algorithm JSSE uses during a TLS handshake,
 * without needing a socket.
 *
 * <p>Given a leaf, zero or more intermediates, and one or more trust anchors,
 * Java tries to construct a chain:
 * <pre>
 *   leaf  →  (intermediates...)  →  a certificate in the truststore
 * </pre>
 * If no such path exists, you get {@code SunCertPathBuilderException:
 * unable to find valid certification path to requested target} — the error
 * Spring Boot clients report as {@code SSLHandshakeException: PKIX path building failed}.
 *
 * <p>This is why trusting the root is necessary but not always sufficient:
 * the builder still has to <em>see</em> every certificate between the leaf and
 * that root. Browsers often download a missing intermediate via the AIA
 * (Authority Information Access) extension. The JDK does not do that by
 * default, so a server that omits the intermediate breaks Java clients even
 * when the root is already trusted.
 */
public final class PkixPathBuilder {

    private PkixPathBuilder() {
    }

    public static PathBuildResult tryBuild(
            X509Certificate leaf,
            List<X509Certificate> intermediates,
            X509Certificate... trustAnchors
    ) {
        try {
            Set<TrustAnchor> anchors = new HashSet<>();
            for (X509Certificate anchor : trustAnchors) {
                anchors.add(new TrustAnchor(anchor, null));
            }

            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(leaf);

            PKIXBuilderParameters parameters = new PKIXBuilderParameters(anchors, selector);
            // Demo certificates have no CRL/OCSP endpoints. Production code may enable this.
            parameters.setRevocationEnabled(false);

            List<X509Certificate> storeCerts = new ArrayList<>();
            storeCerts.add(leaf);
            storeCerts.addAll(intermediates);
            parameters.addCertStore(CertStore.getInstance(
                    "Collection",
                    new CollectionCertStoreParameters(storeCerts)
            ));

            CertPathBuilder.getInstance("PKIX").build(parameters);
            return PathBuildResult.success(
                    "PKIX built a chain from the leaf up to a trusted anchor."
            );
        } catch (CertPathBuilderException ex) {
            return PathBuildResult.failure(rootMessage(ex));
        } catch (Exception ex) {
            return PathBuildResult.failure(rootMessage(ex));
        }
    }

    private static String rootMessage(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current.getClass().getSimpleName() + ": " + current.getMessage();
    }

    public record PathBuildResult(boolean built, String detail) {
        static PathBuildResult success(String detail) {
            return new PathBuildResult(true, detail);
        }

        static PathBuildResult failure(String detail) {
            return new PathBuildResult(false, detail);
        }
    }
}
