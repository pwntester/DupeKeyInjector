package ui;

import application.SAMLEditorTab;
import application.SAMLMessage;
import application.KeyInjector;
import helpers.SAMLHelper;
import helpers.XMLHelper;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import static burp.BurpExtender.*;

public class SAMLEditorPane extends javax.swing.JPanel implements ActionListener {

    private static final long serialVersionUID = 1L;
    private XmlTextPane xmlPane;
    private JEditorPane consolePane;
    private JTextArea certPane;
    private String selectedAction = "restore";
    private SAMLEditorTab tab;

    public SAMLEditorPane(SAMLEditorTab tab) {
        super();
        this.tab = tab;
        initializeUI();
    }

    private void initializeUI(){
        setLayout(new BorderLayout(0, 0));

        // actionPane (xml and buttons)
        JSplitPane actionPane = new JSplitPane();
        actionPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
        actionPane.setDividerLocation(0.8);
        actionPane.setResizeWeight(0.8);

        // XML Editing pane: topPane->xmlBox->scrollPane->xmlPane
        xmlPane = new XmlTextPane();
        JScrollPane scrollPane = new JScrollPane(xmlPane);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setViewportView(xmlPane);
        Box xmlBox = Box.createHorizontalBox();
        xmlBox.setBorder(BorderFactory.createTitledBorder("Edit XML"));
        xmlBox.add(scrollPane);
        JPanel topPane = new JPanel();
        topPane.setLayout(new BorderLayout(0, 0));
        topPane.add(xmlBox);
        actionPane.setTopComponent(topPane);

        // Buttons: centerPane->buttonsBox->Buttons
        JButton original = new JButton("Restore original request");
        original.setActionCommand("restore");
        original.addActionListener(this);
        JButton action1 = new JButton("Re-Sign with RSA Key");
        action1.setActionCommand("rsa");
        action1.addActionListener(this);
        JButton action2 = new JButton("Re-Sign with Public Cert");
        action2.setActionCommand("public_cert");
        action2.addActionListener(this);
        action2.setEnabled(false);
        JButton reset = new JButton("Clear Console");
        reset.setActionCommand("reset");
        reset.addActionListener(this);
        Box buttonsBox = Box.createHorizontalBox();
        buttonsBox.setBorder(BorderFactory.createTitledBorder("Choose action:"));
        buttonsBox.add(original);
        buttonsBox.add(action1);
        buttonsBox.add(action2);
        buttonsBox.add(reset);
        buttonsBox.setSize(buttonsBox.getWidth(), action1.getHeight());
        buttonsBox.validate();
        JSplitPane centerPane = new JSplitPane();
        centerPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
        centerPane.setDividerLocation(0.2);
        centerPane.setResizeWeight(0.2);
        centerPane.setTopComponent(buttonsBox);

        // Certificate: CenterPanel->CertificateBox->CertificatePane
        Box certBox = Box.createHorizontalBox();
        certBox.setBorder(BorderFactory.createTitledBorder("Import Certificate:"));
        certPane = new JTextArea();
        certPane.setEditable(true);
        certPane.setVisible(true);
        certPane.getDocument().addDocumentListener(new DocumentListener() {

            @Override
            public void insertUpdate(DocumentEvent e) {
                if ("".equals(certPane.getText())) {
                    action2.setEnabled(false);
                } else {
                    action2.setEnabled(true);
                }
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                if ("".equals(certPane.getText())) {
                    action2.setEnabled(false);
                } else {
                    action2.setEnabled(true);
                }
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                if ("".equals(certPane.getText())) {
                    action2.setEnabled(false);
                } else {
                    action2.setEnabled(true);
                }
            }
        });
        certPane.setText("");
        certBox.add(certPane);
        centerPane.setBottomComponent(certBox);
        actionPane.setBottomComponent(centerPane);

        // Console: BottomPane->ConsoleBox->scrollBox2->consolePane
        consolePane = new JTextPane();
        consolePane.setEditable(false);
        JScrollPane scrollPane2 = new JScrollPane(consolePane);
        scrollPane2.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane2.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane2.setViewportView(consolePane);
        Box consoleBox = Box.createHorizontalBox();
        consoleBox.setBorder(BorderFactory.createTitledBorder("Console:"));
        consoleBox.add(scrollPane2);
        JPanel bottomPane = new JPanel();
        bottomPane.setLayout(new BorderLayout(0, 0));
        bottomPane.add(consoleBox);

        // Split
        JSplitPane splitPane = new JSplitPane();
        splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPane.setDividerLocation(0.8);
        splitPane.setResizeWeight(0.8);
        splitPane.setTopComponent(actionPane);
        splitPane.setBottomComponent(bottomPane);
        add(splitPane, BorderLayout.CENTER);


        this.invalidate();
        this.updateUI();
    }

    public XmlTextPane getXmlPane(){
        return xmlPane;
    }

    public void printToConsole(String text) {
        String current = consolePane.getText();
        consolePane.setText(current + "\n" + text);
        consolePane.setCaretPosition(consolePane.getText().length());
    }

    public void clearConsole() {
        consolePane.setText("");
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        selectedAction = e.getActionCommand();

        if (selectedAction.equals("reset")) {
            clearConsole();
        } else if (selectedAction.equals("restore")) {
            // Render original request in text panel again
            if (tab.originalRequest == null) {
               printToConsole("[-] No original request");
               return;
            } else {
                printToConsole("[+] Restoring original request");
                SAMLMessage saml = SAMLHelper.getSAMLMessage(tab.originalRequest);
                String message = saml.getMessage();
                try {
                    XMLHelper.isValidXML(message);
                    String indented = XMLHelper.indentXML(message);
                    xmlPane.setText(indented);
                    tab.modified = true;
                } catch (Exception ex) {
                    printToConsole("[-] Invalid XML");
                    ex.printStackTrace(stderr);
                }
            }
        } else if (selectedAction.equals("rsa")) {
            String xml = xmlPane.getText();
            String unindentedXml = xml.replaceAll("(\\r\\n|\\r|\\n)\\s*", "");
            String out = null;
            KeyInjector injector = new KeyInjector(this);
            try {
                out = injector.injectRSAKey(unindentedXml);
                if (XMLHelper.validateRSASignature(XMLHelper.getDocument(out))) {
                    printToConsole("[+] Valid RSA Signature");
                } else {
                    printToConsole("[+] Invalid RSA Signature");
                }
            } catch (Exception ex) {
                printToConsole("[-] Exception injecting key");
                printToConsole(ex.getMessage());
                ex.printStackTrace(stderr);
                return;
            }
            String indented = XMLHelper.indentXML(out);
            xmlPane.setText(indented);
            tab.modified = true;
        } else if (selectedAction.equals("public_cert")) {
            String xml = xmlPane.getText();
            String unindentedXml = xml.replaceAll("(\\r\\n|\\r|\\n)\\s*", "");
            String out = null;
            KeyInjector injector = new KeyInjector(this);
            try {
                // TODO: Import PEM from panel
                String PEM = certPane.getText();
                out = injector.injectEncryptedKey(unindentedXml, PEM);
                XMLHelper.isValidXML(out);
                // TODO: validate signature
            } catch (Exception ex) {
                printToConsole("[-] Exception injecting key");
                printToConsole(ex.getMessage());
                ex.printStackTrace(stderr);
            }
            String indented = XMLHelper.indentXML(out);
            xmlPane.setText(indented);
            tab.modified = true;
        }
    }
}
