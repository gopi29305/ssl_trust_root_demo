package com.example.ssltrust.tls;

import com.example.ssltrust.pki.DemoCertificates;
import com.example.ssltrust.pki.DemoPki;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Isolates the PKIX algorithm from HTTP/TLS so the trust-root rule is visible
 * without starting servers.
 */
class PkixPathBuilderTest {

    private static DemoCertificates certs;

    @BeforeAll
    static void generatePki() {
        certs = DemoPki.generate();
    }

    @Test
    void trustingRootIsEnoughWhenIntermediateIsPresent() {
        PkixPathBuilder.PathBuildResult result = PkixPathBuilder.tryBuild(
                certs.leafCertificate(),
                List.of(certs.intermediateCertificate()),
                certs.rootCertificate()
        );

        assertThat(result.built())
                .as("leaf + intermediate should chain up to the trusted root: %s", result.detail())
                .isTrue();
    }

    @Test
    void trustingRootIsNotEnoughWhenIntermediateIsMissing() {
        PkixPathBuilder.PathBuildResult result = PkixPathBuilder.tryBuild(
                certs.leafCertificate(),
                List.of(),
                certs.rootCertificate()
        );

        assertThat(result.built())
                .as("without the intermediate, PKIX cannot reach the trusted root")
                .isFalse();
        assertThat(result.detail()).containsIgnoringCase("unable to find valid certification path");
    }

    @Test
    void trustingTheIntermediateFillsTheGap() {
        PkixPathBuilder.PathBuildResult result = PkixPathBuilder.tryBuild(
                certs.leafCertificate(),
                List.of(),
                certs.rootCertificate(),
                certs.intermediateCertificate()
        );

        assertThat(result.built())
                .as("trusting the intermediate should complete the path: %s", result.detail())
                .isTrue();
    }

    @Test
    void pinningTheLeafAlsoBuildsAPath() {
        PkixPathBuilder.PathBuildResult result = PkixPathBuilder.tryBuild(
                certs.leafCertificate(),
                List.of(),
                certs.leafCertificate()
        );

        assertThat(result.built()).isTrue();
    }
}
