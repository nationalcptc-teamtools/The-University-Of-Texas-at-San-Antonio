package fieldkit;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** API-backed selected-message fixture, runnable without a Burp installation. */
public final class CaptureHarness {
    private static <T> T fixture(Class<T> type, Map<String, Object> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (proxy, method, arguments) -> {
                    if (!values.containsKey(method.getName()))
                        throw new UnsupportedOperationException(method.getName());
                    return values.get(method.getName());
                }));
    }

    private static ByteArray body(byte[] bytes) {
        return fixture(ByteArray.class, Map.of("length", bytes.length, "getBytes", bytes));
    }

    private static HttpHeader header(String name, String value) {
        return fixture(HttpHeader.class, Map.of("name", name, "value", value));
    }

    public static void main(String[] arguments) throws Exception {
        HttpRequest request = fixture(HttpRequest.class, Map.of(
                "url", "https://fixture.test/account", "method", "POST",
                "headers", List.of(header("Content-Type", "application/json"),
                        header("Authorization", "Bearer fixture-private-auth")),
                "body", body("{\"password\":\"fixture-private-password\"}".getBytes(
                        java.nio.charset.StandardCharsets.UTF_8))));
        HttpResponse response = fixture(HttpResponse.class, Map.of(
                "statusCode", (short) 200,
                "headers", List.of(header("Set-Cookie", "a=fixture-first-cookie"),
                        header("Set-Cookie", "b=fixture-second-cookie")),
                "body", body(new byte[]{0, (byte) 255, 13, 10})));
        HttpRequestResponse pair = fixture(HttpRequestResponse.class, Map.of(
                "request", request, "response", response, "hasResponse", true));
        BridgeClient.Configuration configuration = BridgeClient.Configuration.load(Path.of(arguments[0]));
        String encoded = FieldkitExtension.encode(List.of(pair), "user\"\\\nλ", "employee",
                "account", configuration.maxBytes());
        System.out.print(BridgeClient.send(configuration, encoded));
    }
}
