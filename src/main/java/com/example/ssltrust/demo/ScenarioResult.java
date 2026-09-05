package com.example.ssltrust.demo;

import java.util.List;

/**
 * Outcome of one handshake experiment, returned by the REST API and printed at startup.
 */
public record ScenarioResult(
        String id,
        String title,
        boolean handshakeSucceeded,
        String clientTruststore,
        List<String> serverPresentedChain,
        boolean pkixPathBuilt,
        String pkixDetail,
        String httpBody,
        String error,
        String why
) {
}
