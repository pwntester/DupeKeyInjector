package application;

import burp.*;
import helpers.EncodingHelper;
import helpers.SAMLHelper;
import helpers.XMLHelper;
import ui.SAMLEditorPane;
import ui.XmlTextPane;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

import static burp.BurpExtender.helpers;
import static burp.BurpExtender.stderr;

public class SAMLEditorTab implements IMessageEditorTab {

    private boolean firstLoad = true;
    private IMessageEditorController controller;
    private boolean editable;
    public boolean modified;
    private XmlTextPane textArea;
    public byte[] currentMessage;
    public byte[] originalRequest;
    public IHttpService httpService;
    private SAMLEditorPane panel;
    public SAMLMessage saml;
    public IBurpExtenderCallbacks callbacks;

    public SAMLEditorTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks) {

        this.editable = editable;
        panel = new SAMLEditorPane(this);
        textArea = panel.getXmlPane();
        textArea.addKeyListener(new KeyListener() {

            @Override
            public void keyTyped(KeyEvent arg0) {
            }

            @Override
            public void keyReleased(KeyEvent arg0) {
            }

            @Override
            public void keyPressed(KeyEvent arg0) {
                modified = true;
            }
        });
        textArea.setEditable(true);
        textArea.setEnabled(true);

        this.callbacks = callbacks;
        this.controller = controller;

    }

    @Override
    public String getTabCaption()
    {
        return "Dupe Key Injector";
    }

    @Override
    public Component getUiComponent()
    {
        return panel;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return isRequest && null != SAMLHelper.getSAMLMessage(content);
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (firstLoad) {
            originalRequest = content;
            firstLoad = false;
        }
        modified = false;
        httpService = controller.getHttpService();
        if (content == null) {
            textArea.setText("");
            textArea.setEditable(true);
        } else {
            saml = SAMLHelper.getSAMLMessage(content);
            String message = saml.getMessage();
            try {
                XMLHelper.isValidXML(message);
                String indented = XMLHelper.indentXML(message);
                textArea.setText(indented);
                textArea.setEditable(true);
                currentMessage = content;
            } catch (Exception e) {
                panel.printToConsole("[-] Invalid XML");
                e.printStackTrace(stderr);
            }
        }
    }

    @Override
    public byte[] getMessage() {
        String xml = textArea.getText();
        String unindentedXml = xml.replaceAll("(\\r\\n|\\r|\\n)\\s*", "");

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(currentMessage);
            String encoded = EncodingHelper.encodeMessage(unindentedXml, saml.getEncodings());

            if (saml.getSlotName().equals("body") && saml.getSlotType() == IParameter.PARAM_BODY) {
                // Replace Request body
                int bodyOffset = requestInfo.getBodyOffset();
                String headers = new String(currentMessage, 0, bodyOffset, "UTF-8");
                String newMessage = headers + encoded;
                return newMessage.getBytes("UTF-8");
            } else {
                // Replace Request parameter
                IParameter param = helpers.buildParameter(saml.getSlotName(), encoded, saml.getSlotType());
                return helpers.updateParameter(currentMessage, param);
            }

        } catch (Exception ex) {
            panel.printToConsole("[-] Something went wrong sorry! Check plugin stderr");
            ex.printStackTrace(stderr);
        }
        return currentMessage;
    }

    @Override
    public boolean isModified() {
        return modified;
    }

    @Override
    public byte[] getSelectedData() {
        return helpers.stringToBytes(textArea.getSelectedText());
    }
}
