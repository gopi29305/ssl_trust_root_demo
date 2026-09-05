package com.example.ssltrust.tls;

import com.example.ssltrust.pki.DemoCertificates;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Opens a TLS socket with a trust-all manager so we can report the certificate
 * chain the server actually sent, independent of whether our real client would
 * accept it.
 *
 * <p>This is how the demo proves the two upstreams differ: one presents
 * {@code [leaf, intermediate]} and the other presents {@code [leaf]}.
 */
public final class PresentedChainInspector {

    private PresentedChainInspector() {
    }

    public static List<String> inspect(String host, int port) {
        try {
            SSLSocketFactory factory = TlsSupport.trustAllForInspectionOnly().getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                SSLParameters parameters = socket.getSSLParameters();
                parameters.setServerNames(List.of(new SNIHostName("localhost")));
                // Endpoint identification is skipped here on purpose: we only want
                // to read the peer chain, not validate it.
                socket.setSSLParameters(parameters);
                socket.setSoTimeout(5_000);
                socket.startHandshake();
                Certificate[] chain = socket.getSession().getPeerCertificates();
                return Arrays.stream(chain)
                        .map(X509Certificate.class::cast)
                        .map(DemoCertificates::subject)
                        .toList();
            }
        } catch (Exception ex) {
            return List.of("(unable to inspect presented chain: " + ex.getMessage() + ")");
        }
    }
}
