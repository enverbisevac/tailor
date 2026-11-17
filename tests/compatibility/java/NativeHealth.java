import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class NativeHealth {
    static {
        System.load("/opt/tailor/libhealth.so");
    }

    private static native int answer();

    public static void main(String[] args) throws Exception {
        if (answer() != 42) throw new IllegalStateException("JNI call failed");
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0);
        server.createContext("/health", exchange -> {
            byte[] body = "{\"status\":\"ok\",\"runtime\":\"java\",\"native\":true,\"answer\":42}"
                .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (var output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        server.start();
    }
}
