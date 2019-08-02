package burp;

import application.SAMLEditorTabFactory;
import org.apache.xml.security.Init;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;

    private static final String PLUGIN_NAME = "Dupe Key Injector";

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        Init.init();

        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        this.helpers = callbacks.getHelpers();

        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // set our extension name
        callbacks.setExtensionName(PLUGIN_NAME);

        // register the message editor tab factory
        SAMLEditorTabFactory messageEditorTabFactory = new SAMLEditorTabFactory(callbacks);
        callbacks.registerMessageEditorTabFactory(messageEditorTabFactory);
    }


}

