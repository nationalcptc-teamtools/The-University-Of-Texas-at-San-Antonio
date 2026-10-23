package fieldkit;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.RejectedExecutionException;
import javax.swing.*;

/** Explicit selected-message handoff; does not intercept or rewrite target traffic. */
public final class FieldkitExtension implements BurpExtension {
    private final JTextField config = new JTextField(45), user = new JTextField(20),
            role = new JTextField(20), feature = new JTextField(20);
    private final JTextArea status = new JTextArea(8, 60);
    private final ThreadPoolExecutor worker = new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(4), runnable -> {
                Thread thread = new Thread(runnable, "Fieldkit capture sender");
                thread.setDaemon(true); return thread;
            });

    @Override public void initialize(MontoyaApi api) {
        api.extension().setName("Send to Fieldkit");
        api.extension().registerUnloadingHandler(worker::shutdownNow);
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override public List<Component> provideMenuItems(ContextMenuEvent event) {
                return menu(event);
            }
        });
        JPanel fields = new JPanel(new GridLayout(0, 2, 8, 8));
        JButton browse = new JButton("Select receiver configuration");
        browse.addActionListener(event -> {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION)
                config.setText(chooser.getSelectedFile().getAbsolutePath());
        });
        fields.add(browse); fields.add(config);
        fields.add(new JLabel("Captured user")); fields.add(user);
        fields.add(new JLabel("Captured role")); fields.add(role);
        fields.add(new JLabel("Feature")); fields.add(feature);
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.add(new JLabel("Start Fieldkit's Burp bridge, select its private configuration, then right-click messages → Send to Fieldkit."), BorderLayout.NORTH);
        panel.add(fields, BorderLayout.CENTER); status.setEditable(false);
        panel.add(new JScrollPane(status), BorderLayout.SOUTH);
        api.userInterface().registerSuiteTab("Fieldkit", panel);
        show("Ready. Select requests in Proxy history or Repeater to send them.");
    }

    private List<Component> menu(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = new ArrayList<>(event.selectedRequestResponses());
        if (selected.isEmpty()) event.messageEditorRequestResponse()
                .ifPresent(editor -> selected.add(editor.requestResponse()));
        if (selected.isEmpty()) return List.of();
        JMenuItem send = new JMenuItem("Send to Fieldkit");
        send.addActionListener(action -> {
            String filename = config.getText().trim(), capturedUser = user.getText(),
                    capturedRole = role.getText(), capturedFeature = feature.getText();
            try {
                worker.execute(() -> {
                    try {
                        BridgeClient.Configuration configuration = BridgeClient.Configuration.load(Path.of(filename));
                        if (selected.size() > configuration.maxEntries()) {
                            show("Select at most " + configuration.maxEntries() + " messages per send."); return;
                        }
                        show(BridgeClient.send(configuration, encode(selected, capturedUser,
                                capturedRole, capturedFeature, configuration.maxBytes())));
                    } catch (Exception error) {
                        // Exception text can contain secrets; display a fixed diagnostic.
                        show("Capture failed. Check receiver status, private configuration, selected origins and size limits.");
                    }
                });
            } catch (RejectedExecutionException error) { show("Capture queue is full; wait for previous sends."); }
        });
        return List.of(send);
    }

    public static String encode(List<HttpRequestResponse> messages, String user, String role,
            String feature, int maximum) {
        if (user.length() > 256 || role.length() > 256 || feature.length() > 256)
            throw new IllegalArgumentException("Context size limit");
        StringBuilder output = new StringBuilder("{\"schema_version\":1,\"tags\":[\"burp\"],\"context\":{");
        output.append("\"user\":").append(BridgeClient.quote(user));
        output.append(",\"role\":").append(BridgeClient.quote(role));
        output.append(",\"feature\":").append(BridgeClient.quote(feature)).append("},\"exchanges\":[");
        boolean first = true;
        for (HttpRequestResponse pair : messages) {
            if (!first) output.append(','); first = false;
            output.append("{\"request\":{\"url\":").append(BridgeClient.quote(pair.request().url()));
            output.append(",\"method\":").append(BridgeClient.quote(pair.request().method()));
            appendMessage(output, pair.request(), maximum); output.append('}');
            if (pair.hasResponse()) {
                output.append(",\"response\":{\"status\":").append(pair.response().statusCode());
                appendMessage(output, pair.response(), maximum); output.append('}');
            }
            output.append('}');
            if (output.length() > maximum) throw new IllegalArgumentException("Capture size limit");
        }
        return output.append("]}").toString();
    }

    private static void appendMessage(StringBuilder output, HttpMessage message, int maximum) {
        if (message.body().length() > maximum || message.headers().size() > 200)
            throw new IllegalArgumentException("Capture size limit");
        output.append(",\"headers\":["); boolean first = true;
        for (var header : message.headers()) {
            if (!first) output.append(','); first = false;
            output.append("{\"name\":").append(BridgeClient.quote(header.name()));
            output.append(",\"value\":").append(BridgeClient.quote(header.value())).append('}');
            if (output.length() > maximum) throw new IllegalArgumentException("Capture size limit");
        }
        output.append("],\"body_base64\":");
        output.append(BridgeClient.quote(Base64.getEncoder().encodeToString(message.body().getBytes())));
    }

    private void show(String text) { SwingUtilities.invokeLater(() -> status.setText(text)); }
}
