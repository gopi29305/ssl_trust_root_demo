package com.example.ssltrust;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot 3.5 demo of Java TLS trust-anchor behavior.
 *
 * <p>The question this app answers:
 * <blockquote>
 * If a HTTPS server presents a certificate chain of root + intermediate + leaf,
 * do I only need to trust the root in the Java client truststore?
 * </blockquote>
 *
 * <p><b>Yes</b>, with one important caveat that this project proves live:
 * <ul>
 *   <li><b>Success:</b> client truststore contains the <em>root only</em>, and the
 *       server sends <em>leaf + intermediate</em>. Java builds
 *       {@code leaf → intermediate → trusted root} and the handshake succeeds.</li>
 *   <li><b>Failure:</b> client truststore still contains the root only, but the
 *       server sends the <em>leaf only</em>. Java does not fetch missing
 *       intermediates the way browsers often do, so PKIX path building fails
 *       even though the root is trusted.</li>
 * </ul>
 *
 * <p>On startup the app:
 * <ol>
 *   <li>Generates a private Root CA → Intermediate CA → localhost leaf chain.</li>
 *   <li>Starts two local HTTPS "upstream APIs" that use the same leaf key, but
 *       advertise different chains.</li>
 *   <li>Calls both of them with a {@code RestClient} whose truststore holds
 *       only the root.</li>
 *   <li>Exposes the same experiment at {@code GET /api/ssl-demo}.</li>
 * </ol>
 */
@SpringBootApplication
public class SslTrustRootDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SslTrustRootDemoApplication.class, args);
    }
}
