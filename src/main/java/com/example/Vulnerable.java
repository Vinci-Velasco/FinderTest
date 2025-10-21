// VulnerableServer.java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Map;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class Vulnerable {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/run", new RunHandler());
        server.start();
        System.out.println("VulnerableServer listening on http://localhost:8000/run?request=...");
    }

    static class RunHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            URI uri = exchange.getRequestURI();
            String query = uri.getRawQuery(); // e.g. "request=foo"
            Map<String, String> params = parseQuery(query);
            String userRequest = params.getOrDefault("request", "");

            // ===== VULNERABLE: concatenating untrusted input into a shell command =====
            // This hands a single string to the OS command runner, which may invoke a shell.
            String cmd = "mytool " + userRequest;
            StringBuilder output = new StringBuilder();
            try {
                Process p = Runtime.getRuntime().exec(cmd);
                try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                    String line;
                    while ((line = r.readLine()) != null) output.append(line).append("\n");
                }
            } catch (Exception e) {
                output.append("error: ").append(e.getMessage());
            }

            byte[] resp = output.toString().getBytes();
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        }
    }

    // Very small query parser (does not decode '+' or %-encoding; fine for demo)
    private static Map<String, String> parseQuery(String q) {
        if (q == null || q.isEmpty()) return Map.of();
        return Map.ofEntries(
            java.util.Arrays.stream(q.split("&"))
                .map(s -> {
                    String[] kv = s.split("=", 2);
                    String k = kv[0];
                    String v = kv.length > 1 ? kv[1] : "";
                    return Map.entry(k, v);
                })
                .toArray(Map.Entry[]::new)
        );
    }
}