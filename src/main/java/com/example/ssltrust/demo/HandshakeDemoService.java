package com.example.ssltrust.demo;

import com.example.ssltrust.client.TrustedHttpsClientFactory;
import com.example.ssltrust.pki.DemoCertificates;
import com.example.ssltrust.tls.PkixPathBuilder;
import com.example.ssltrust.tls.PresentedChainInspector;
import com.example.ssltrust.upstream.UpstreamHttpsServer;
import com.example.ssltrust.upstream.UpstreamServerPair;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import javax.net.ssl.SSLHandshakeException;
import java.util.List;

/**
 * Runs the TLS experiments that answer: "is trusting the root enough?"
 *
 * <p>All outbound calls go through Spring {@link RestClient}, which is the
 * modern replacement for {@code RestTemplate} in Spring Boot 3.5. Each client
 * is given a different truststore so we can isolate the effect of which
 * certificates Java considers trust anchors.
 *
 * <ol>
 *   <li>{@link #trustRootAndServerSendsFullChain()} — the expected production
 *       setup. Handshake <b>succeeds</b>.</li>
 *   <li>{@link #trustRootButServerOmitsIntermediate()} — the same truststore,
 *       but the server hides the intermediate. Handshake <b>fails</b> with
 *       PKIX path building. This is the counter-example.</li>
 *   <li>{@link #workaroundTrustIntermediateToo()} — importing the missing
 *       intermediate into the client truststore makes the leaf-only server
 *       work. Valid workaround, but you now have to rotate truststores when
 *       intermediates change.</li>
 *   <li>{@link #workaroundPinTheLeaf()} — pinning the server certificate
 *       itself also works, and is even more brittle.</li>
 * </ol>
 */
@Service
public class HandshakeDemoService {

    private final DemoCertificates certificates;
    private final UpstreamServerPair upstreams;
    private final RestClient rootOnlyClient;
    private final RestClient rootAndIntermediateClient;
    private final RestClient leafPinnedClient;

    public HandshakeDemoService(DemoCertificates certificates, UpstreamServerPair upstreams) {
        this.certificates = certificates;
        this.upstreams = upstreams;
        this.rootOnlyClient = TrustedHttpsClientFactory.trusting(certificates.rootCertificate());
        this.rootAndIntermediateClient = TrustedHttpsClientFactory.trusting(
                certificates.rootCertificate(),
                certificates.intermediateCertificate()
        );
        this.leafPinnedClient = TrustedHttpsClientFactory.trusting(certificates.leafCertificate());
    }

    public List<ScenarioResult> runAll() {
        return List.of(
                trustRootAndServerSendsFullChain(),
                trustRootButServerOmitsIntermediate(),
                workaroundTrustIntermediateToo(),
                workaroundPinTheLeaf()
        );
    }

    /**
     * Happy path: truststore = root only, server sends leaf + intermediate.
     *
     * <p>Java walks {@code leaf → intermediate} from the handshake, then
     * {@code intermediate → root} using the truststore. That is a complete
     * path to a trust anchor, so the handshake succeeds. This is why the
     * answer to "do I just need the root?" is yes — <em>when the chain is complete</em>.
     */
    public ScenarioResult trustRootAndServerSendsFullChain() {
        return invoke(
                "trust-root-full-chain",
                "Trust the root; server sends leaf + intermediate",
                rootOnlyClient,
                upstreams.fullChain(),
                List.of(certificates.intermediateCertificate()),
                certificates.rootCertificate(),
                """
                The client truststore holds only the Root CA. The server presents \
                the leaf and the intermediate. PKIX can build leaf → intermediate → \
                trusted root, so the TLS handshake succeeds. This is the correct \
                production setup: import the root (or the organization's issuing CA), \
                and make sure the remote API sends a complete chain.
                """
        );
    }

    /**
     * Counter-example: the root is still trusted, but the path cannot be built
     * because the intermediate is not in the handshake and not in the truststore.
     *
     * <p>This is the situation people hit when:
     * <ul>
     *   <li>A browser can open the URL (it downloaded the intermediate via AIA), but</li>
     *   <li>{@code RestClient}/{@code RestTemplate}/{@code WebClient} throws
     *       {@code SSLHandshakeException: PKIX path building failed} /
     *       {@code unable to find valid certification path to requested target}.</li>
     * </ul>
     * Trusting the root did not help, because Java never saw a candidate path
     * that reached that root.
     */
    public ScenarioResult trustRootButServerOmitsIntermediate() {
        return invoke(
                "trust-root-leaf-only",
                "Trust the root; server sends leaf only (intermediate missing)",
                rootOnlyClient,
                upstreams.leafOnly(),
                List.of(),
                certificates.rootCertificate(),
                """
                The client still trusts the Root CA, but the server presents only \
                the leaf. Java does not fetch the missing intermediate (browsers \
                often will, via AIA). The path is leaf → ??? → root, so PKIX path \
                building fails even though the root is in the truststore. Fix this \
                on the server (send the full chain) or, as a client workaround, \
                also trust the intermediate.
                """
        );
    }

    /**
     * Workaround: put the intermediate in the truststore as well. The leaf-only
     * server now succeeds because the intermediate itself becomes a trust anchor
     * (or at least is available to complete the path).
     */
    public ScenarioResult workaroundTrustIntermediateToo() {
        return invoke(
                "workaround-trust-intermediate",
                "Workaround: trust root + intermediate; server still sends leaf only",
                rootAndIntermediateClient,
                upstreams.leafOnly(),
                List.of(),
                certificates.rootCertificate(),
                certificates.intermediateCertificate(),
                """
                Importing the intermediate into the client truststore fills the gap \
                the server left. Handshake succeeds, but the client now depends on \
                a specific intermediate remaining valid. Prefer fixing the server \
                chain (send leaf + intermediate) and trusting only the root.
                """
        );
    }

    /**
     * Workaround: pin the leaf. Works, but the truststore must be updated on
     * every certificate renewal.
     */
    public ScenarioResult workaroundPinTheLeaf() {
        return invoke(
                "workaround-pin-leaf",
                "Workaround: pin the leaf certificate; server sends leaf only",
                leafPinnedClient,
                upstreams.leafOnly(),
                List.of(),
                certificates.leafCertificate(),
                """
                Trusting the leaf itself (certificate pinning) also produces a \
                valid path of length 1. This ignores the rest of the CA hierarchy \
                and breaks as soon as the server rotates its certificate. Useful \
                as a last resort, not as a general trust strategy.
                """
        );
    }

    public DemoCertificates certificates() {
        return certificates;
    }

    public UpstreamServerPair upstreams() {
        return upstreams;
    }

    private ScenarioResult invoke(
            String id,
            String title,
            RestClient client,
            UpstreamHttpsServer server,
            List<java.security.cert.X509Certificate> intermediatesForPkix,
            java.security.cert.X509Certificate trustAnchor,
            String why
    ) {
        return invoke(id, title, client, server, intermediatesForPkix, why, trustAnchor);
    }

    private ScenarioResult invoke(
            String id,
            String title,
            RestClient client,
            UpstreamHttpsServer server,
            List<java.security.cert.X509Certificate> intermediatesForPkix,
            java.security.cert.X509Certificate firstAnchor,
            java.security.cert.X509Certificate secondAnchor,
            String why
    ) {
        return invoke(id, title, client, server, intermediatesForPkix, why, firstAnchor, secondAnchor);
    }

    private ScenarioResult invoke(
            String id,
            String title,
            RestClient client,
            UpstreamHttpsServer server,
            List<java.security.cert.X509Certificate> intermediatesForPkix,
            String why,
            java.security.cert.X509Certificate... trustAnchors
    ) {
        List<String> presented = PresentedChainInspector.inspect("127.0.0.1", server.port());
        PkixPathBuilder.PathBuildResult pkix = PkixPathBuilder.tryBuild(
                certificates.leafCertificate(),
                intermediatesForPkix,
                trustAnchors
        );

        try {
            String body = client.get()
                    .uri(server.pingUrl())
                    .retrieve()
                    .body(String.class);
            return new ScenarioResult(
                    id,
                    title,
                    true,
                    describeTruststore(trustAnchors),
                    presented,
                    pkix.built(),
                    pkix.detail(),
                    body,
                    null,
                    why.trim()
            );
        } catch (Exception ex) {
            return new ScenarioResult(
                    id,
                    title,
                    false,
                    describeTruststore(trustAnchors),
                    presented,
                    pkix.built(),
                    pkix.detail(),
                    null,
                    describeTlsError(ex),
                    why.trim()
            );
        }
    }

    private static String describeTruststore(java.security.cert.X509Certificate... trustAnchors) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < trustAnchors.length; i++) {
            if (i > 0) {
                builder.append(" + ");
            }
            builder.append(DemoCertificates.subject(trustAnchors[i]));
        }
        return builder.toString();
    }

    /**
     * Prefer the {@link SSLHandshakeException} message when present. That is the
     * wrapping error developers actually search for:
     * {@code PKIX path building failed ... unable to find valid certification path}.
     * The deepest cause is {@code SunCertPathBuilderException}, which is the same
     * failure one layer down.
     */
    static String describeTlsError(Throwable throwable) {
        Throwable current = throwable;
        SSLHandshakeException handshake = null;
        Throwable deepest = throwable;
        while (current != null) {
            deepest = current;
            if (current instanceof SSLHandshakeException sslHandshakeException && handshake == null) {
                handshake = sslHandshakeException;
            }
            if (current.getCause() == current) {
                break;
            }
            current = current.getCause();
        }
        Throwable chosen = handshake != null ? handshake : deepest;
        return chosen.getClass().getSimpleName() + ": " + chosen.getMessage();
    }
}
