package com.example.ssltrust.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SslDemoControllerTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void indexListsTheDemoEndpoints() {
        ResponseEntity<Map> response = restTemplate.getForEntity(url("/"), Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKeys(
                "allScenarios",
                "fullChainSuccess",
                "leafOnlyFailure"
        );
    }

    @Test
    void fullChainEndpointReportsASuccessfulHandshake() {
        ResponseEntity<Map> response = restTemplate.getForEntity(url("/api/ssl-demo/full-chain"), Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("handshakeSucceeded")).isEqualTo(true);
        assertThat((String) response.getBody().get("id")).isEqualTo("trust-root-full-chain");
    }

    @Test
    void leafOnlyEndpointReportsTheExpectedPkixFailure() {
        ResponseEntity<Map> response = restTemplate.getForEntity(url("/api/ssl-demo/leaf-only"), Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("handshakeSucceeded")).isEqualTo(false);
        assertThat((String) response.getBody().get("error")).contains("PKIX");
    }

    @Test
    void allScenariosEndpointReturnsFourResults() {
        ResponseEntity<List> response = restTemplate.getForEntity(url("/api/ssl-demo"), List.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).hasSize(4);
    }

    @Test
    void pkiEndpointDescribesTheGeneratedHierarchy() {
        ResponseEntity<Map> response = restTemplate.getForEntity(url("/api/ssl-demo/pki"), Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKeys("root", "intermediate", "leaf");
    }

    private String url(String path) {
        return "http://127.0.0.1:" + port + path;
    }
}
