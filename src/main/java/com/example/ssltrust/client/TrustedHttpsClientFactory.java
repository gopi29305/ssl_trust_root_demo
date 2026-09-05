package com.example.ssltrust.client;

import com.example.ssltrust.tls.TlsSupport;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import javax.net.ssl.SSLContext;
import java.net.http.HttpClient;
import java.security.cert.X509Certificate;
import java.time.Duration;

/**
 * Builds a Spring {@link RestClient} whose JVM {@link SSLContext} trusts only
 * the certificates we pass in — typically the Root CA.
 *
 * <p>This is the programmatic equivalent of:
 * <pre>
 *   keytool -importcert -alias root -file root.crt -keystore truststore.p12
 *   java -Djavax.net.ssl.trustStore=truststore.p12 ...
 * </pre>
 * or a Spring Boot 3.1+ SSL bundle:
 * <pre>
 *   spring.ssl.bundle.jks.upstream.truststore.location=classpath:root-only.p12
 * </pre>
 *
 * <p>Note that {@code server.ssl.*} in {@code application.yml} configures the
 * <em>incoming</em> HTTPS connector of this Spring Boot app. Outbound calls
 * (RestClient / RestTemplate / WebClient) use a separate SSL context, which
 * is what we customize here.
 */
public final class TrustedHttpsClientFactory {

    private TrustedHttpsClientFactory() {
    }

    public static RestClient trusting(X509Certificate... trustAnchors) {
        try {
            SSLContext sslContext = TlsSupport.clientSslContext(TlsSupport.trustStore(trustAnchors));
            HttpClient httpClient = HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();
            JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
            requestFactory.setReadTimeout(Duration.ofSeconds(5));
            return RestClient.builder()
                    .requestFactory(requestFactory)
                    .build();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to create TLS RestClient", ex);
        }
    }
}
