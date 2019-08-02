package application;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class SAMLEditorTabFactory implements IMessageEditorTabFactory {

    IBurpExtenderCallbacks callbacks;

    public SAMLEditorTabFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        return new SAMLEditorTab(controller, editable, callbacks);
    }
}
