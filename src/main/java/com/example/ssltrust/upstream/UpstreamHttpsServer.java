package com.example.ssltrust.upstream;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.SSLContext;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Tiny JDK HTTPS server that stands in for "the other API" your Spring Boot
 * service calls.
 *
 * <p>The only thing that changes between the two instances is the
 * {@link SSLContext}: one was built from a keystore whose chain is
 * {@code [leaf, intermediate]}, the other from {@code [leaf]} only. The
 * HTTP handler is identical.
 *
 * <p>{@code com.sun.net.httpserver.HttpsServer} is part of the JDK
 * ({@code jdk.httpserver} module). It is used here so the presented TLS chain
 * is under our control without bringing in a second Spring Boot app.
 */
public final class UpstreamHttpsServer implements AutoCloseable {

    private final String name;
    private final HttpsServer server;
    private final ExecutorService executor;

    private UpstreamHttpsServer(String name, HttpsServer server, ExecutorService executor) {
        this.name = name;
        this.server = server;
        this.executor = executor;
    }

    public static UpstreamHttpsServer start(String name, SSLContext sslContext, String body) {
        try {
            HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(sslContext));
            server.createContext("/api/ping", exchange -> {
                byte[] response = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream output = exchange.getResponseBody()) {
                    output.write(response);
                }
            });
            ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
                Thread thread = new Thread(runnable, "upstream-" + name);
                thread.setDaemon(true);
                return thread;
            });
            server.setExecutor(executor);
            server.start();
            return new UpstreamHttpsServer(name, server, executor);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to start upstream HTTPS server '" + name + "'", ex);
        }
    }

    public String name() {
        return name;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public String baseUrl() {
        return "https://127.0.0.1:" + port();
    }

    public String pingUrl() {
        return baseUrl() + "/api/ping";
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }
}
