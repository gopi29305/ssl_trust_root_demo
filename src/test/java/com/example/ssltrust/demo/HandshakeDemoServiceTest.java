package com.example.ssltrust.demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class HandshakeDemoServiceTest {

    @Autowired
    private HandshakeDemoService demoService;

    @Test
    void trustingOnlyTheRootSucceedsWhenTheServerSendsTheFullChain() {
        ScenarioResult result = demoService.trustRootAndServerSendsFullChain();

        assertThat(result.handshakeSucceeded()).isTrue();
        assertThat(result.pkixPathBuilt()).isTrue();
        assertThat(result.clientTruststore()).contains("Demo Root CA");
        assertThat(result.clientTruststore()).doesNotContain("Intermediate");
        assertThat(result.serverPresentedChain()).hasSize(2);
        assertThat(result.serverPresentedChain().get(0)).contains("localhost");
        assertThat(result.serverPresentedChain().get(1)).contains("Intermediate");
        assertThat(result.httpBody()).contains("full-chain");
        assertThat(result.error()).isNull();
    }

    @Test
    void trustingOnlyTheRootFailsWhenTheServerOmitsTheIntermediate() {
        ScenarioResult result = demoService.trustRootButServerOmitsIntermediate();

        assertThat(result.handshakeSucceeded())
                .as("root in the truststore is not enough if the intermediate never appears")
                .isFalse();
        assertThat(result.pkixPathBuilt()).isFalse();
        assertThat(result.clientTruststore()).contains("Demo Root CA");
        assertThat(result.serverPresentedChain()).hasSize(1);
        assertThat(result.serverPresentedChain().getFirst()).contains("localhost");
        assertThat(result.httpBody()).isNull();
        assertThat(result.error()).containsIgnoringCase("PKIX");
        assertThat(result.error()).containsIgnoringCase("unable to find valid certification path");
    }

    @Test
    void importingTheIntermediateLetsTheLeafOnlyServerSucceed() {
        ScenarioResult result = demoService.workaroundTrustIntermediateToo();

        assertThat(result.handshakeSucceeded()).isTrue();
        assertThat(result.serverPresentedChain()).hasSize(1);
        assertThat(result.httpBody()).contains("leaf-only");
    }

    @Test
    void pinningTheLeafLetsTheLeafOnlyServerSucceed() {
        ScenarioResult result = demoService.workaroundPinTheLeaf();

        assertThat(result.handshakeSucceeded()).isTrue();
        assertThat(result.httpBody()).contains("leaf-only");
    }
}
