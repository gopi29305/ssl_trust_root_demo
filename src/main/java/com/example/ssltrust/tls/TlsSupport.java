package com.example.ssltrust.tls;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Small helpers around JSSE {@link KeyStore} / {@link SSLContext} construction.
 *
 * <p>Two facts drive this entire demo:
 * <ol>
 *   <li><b>The server chain is the certificate array stored with the private key.</b>
 *       {@link KeyStore#setKeyEntry} is how we control whether the upstream presents
 *       {@code [leaf, intermediate]} or {@code [leaf]} during the handshake.</li>
 *   <li><b>The client truststore holds trust anchors, not the whole chain.</b>
 *       Importing only the root is the correct production setup — as long as the
 *       server sends the intermediates needed to walk up to that root.</li>
 * </ol>
 */
public final class TlsSupport {

    public static final char[] KEYSTORE_PASSWORD = "changeit".toCharArray();

    private TlsSupport() {
    }

    /**
     * Server identity keystore. The {@code chain} argument is exactly what JSSE
     * will send to the client in the TLS {@code Certificate} handshake message.
     *
     * <p>Typical correct chain: {@code [leaf, intermediate]}. The root is usually
     * omitted because the client is expected to already have it as a trust anchor.
     *
     * <p>Broken chain used by this demo: {@code [leaf]} — missing intermediate.
     */
    public static KeyStore serverKeyStore(java.security.PrivateKey leafKey, X509Certificate... chain)
            throws Exception {
        KeyStore keyStore = emptyPkcs12();
        keyStore.setKeyEntry("server", leafKey, KEYSTORE_PASSWORD, chain);
        return keyStore;
    }

    /**
     * Client truststore. Each certificate added here is treated as a <em>trust
     * anchor</em> by the PKIX path builder. It does not have to be a root; an
     * intermediate (or even the leaf) can also be an anchor, which is why
     * "just import the missing intermediate" is a common workaround.
     */
    public static KeyStore trustStore(X509Certificate... trustedCertificates) throws Exception {
        KeyStore trustStore = emptyPkcs12();
        for (int i = 0; i < trustedCertificates.length; i++) {
            trustStore.setCertificateEntry("trusted-" + i, trustedCertificates[i]);
        }
        return trustStore;
    }

    public static SSLContext serverSslContext(KeyStore serverKeyStore) throws Exception {
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(serverKeyStore, KEYSTORE_PASSWORD);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers.getKeyManagers(), null, new SecureRandom());
        return sslContext;
    }

    public static SSLContext clientSslContext(KeyStore trustStore) throws Exception {
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trustStore);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagers.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    /**
     * Diagnostic-only SSLContext that accepts any server certificate.
     *
     * <p>Used solely to inspect the chain the peer actually sent. Never use a
     * trust-all manager for real outbound calls — it disables the entire point
     * of TLS authentication.
     */
    public static SSLContext trustAllForInspectionOnly() throws Exception {
        TrustManager trustAll = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
                // inspection only
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // inspection only
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustAll}, new SecureRandom());
        return sslContext;
    }

    public static String describeChain(Certificate[] chain) {
        return Arrays.stream(chain)
                .map(X509Certificate.class::cast)
                .map(cert -> cert.getSubjectX500Principal().getName())
                .reduce((left, right) -> left + " -> " + right)
                .orElse("(empty)");
    }

    private static KeyStore emptyPkcs12() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, KEYSTORE_PASSWORD);
        return keyStore;
    }
}
