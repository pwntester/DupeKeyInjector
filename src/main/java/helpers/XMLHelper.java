package helpers;

import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.*;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static burp.BurpExtender.stderr;

public class XMLHelper {

    public static boolean validateRSASignature(Document document) throws Exception {

        setIDAttribute(document);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Find Signature element.
        NodeList nl = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }

        // Create a DOMValidateContext and specify a KeySelector and document context.
        DOMValidateContext valContext = new DOMValidateContext(new RSAKeySelector(), nl.item(0));

        // Unmarshal the XMLSignature
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        // Validate the XMLSignature.
        boolean coreValidity = signature.validate(valContext);

        // Check core validation status.
        if (coreValidity == false) {
            boolean sv = signature.getSignatureValue().validate(valContext);
            if (sv == false) {
                    // Check the validation status of each Reference.
                    @SuppressWarnings("rawtypes")
                    Iterator i = signature.getSignedInfo().getReferences().iterator();
                    for (int j = 0; i.hasNext(); j++) {
                        boolean refValid = ((Reference) i.next()).validate(valContext);
                        System.out.println("ref[" + j + "] validity status: " + refValid);
                    }
            }
        }
        return coreValidity;
    }

    public static String getStringOfDocument(Document document, int indent, boolean indenting) throws Exception{
        document.normalize();
        removeEmptyTags(document);
        return getString(document, indenting, indent);
    }

    public static String getString(Document document, boolean indenting, int indent) throws Exception{
        OutputFormat format = new OutputFormat(document);
        format.setLineWidth(0);
        format.setIndenting(indenting);
        format.setIndent(indent);
        format.setPreserveEmptyAttributes(true);
        format.setEncoding("UTF-8");
        format.setOmitXMLDeclaration(true);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLSerializer serializer = new XMLSerializer(baos, format);
        serializer.asDOMSerializer();
        serializer.serialize(document);

        String out = baos.toString("UTF-8");
        return out; //.replace("\n", "");
    }

    public static void removeEmptyTags(Document document) {
        NodeList nl = null;
        try {
            XPath xPath = XPathFactory.newInstance().newXPath();
            nl = (NodeList) xPath.evaluate("//text()[normalize-space(.)='']", document, XPathConstants.NODESET);

            for (int i = 0; i < nl.getLength(); ++i) {
                Node node = nl.item(i);
                node.getParentNode().removeChild(node);
            }

        } catch (XPathExpressionException e) {
            e.printStackTrace(stderr);
        }
    }

    public static void trimWhitespace(Node node) {
        NodeList children = node.getChildNodes();
        for(int i = 0; i < children.getLength(); ++i) {
            Node child = children.item(i);
            if(child.getNodeType() == Node.TEXT_NODE) {
                child.setTextContent(child.getTextContent().trim());
            }
            trimWhitespace(child);
        }
    }

    public static void addNSPrefix(Node node, String prefix) {
        node.setPrefix(prefix);
        NodeList children = node.getChildNodes();
        for(int i = 0; i < children.getLength(); ++i) {
            Node child = children.item(i);
            try {
                child.setPrefix(prefix);
                addNSPrefix(child, prefix);
            } catch (Exception e) {}
        }
    }

    public static X509Certificate convertToX509Cert(String certificateString) throws CertificateException {
        X509Certificate certificate = null;
        CertificateFactory cf = null;
        try {
            if (certificateString != null && !certificateString.trim().isEmpty()) {
                certificateString = certificateString
                        .replace("-----BEGIN CERTIFICATE-----\n", "")
                        .replace("-----END CERTIFICATE-----", ""); // NEED FOR PEM FORMAT CERT STRING
                byte[] certificateData = Base64.getDecoder().decode(certificateString.replace("\n", ""));
                cf = CertificateFactory.getInstance("X509");
                certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
            }
        } catch (CertificateException e) {
            throw new CertificateException(e);
        }
        return certificate;
    }

    public static KeyPair createKeyPair() {
        KeyPair keyPair = null;

        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(512);
            keyPair = keygen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace(stderr);
            return null;
        }
        return keyPair;
    }

    public static void signAssertion(Document document, PublicKey public_key, Key signing_key) throws Exception {
        setIDAttribute(document);
        XPath xpath = XPathFactory.newInstance().newXPath();
        XPathExpression expr = xpath.compile("//*[local-name()='Assertion']/@*[local-name()='ID' or local-name()='id' or local-name()='AssertionID' or local-name()='AssertionId']");
        NodeList nlURIs = (NodeList) expr.evaluate(document, XPathConstants.NODESET);

        if (nlURIs.getLength() == 0) throw new Exception("Cant find Assertion");

        String[] sigIDs = new String[nlURIs.getLength()];

        for (int i = 0; i < nlURIs.getLength(); i++) {
            sigIDs[i] = nlURIs.item(i).getNodeValue();
        }

        for (String id : sigIDs) {
            signElement(document, id, public_key, signing_key);
        }
    }

    public static Document signElement(Document doc, String id, PublicKey public_key, Key signing_key) throws Exception {

        String signAlg = "";
        //String digestAlg = "http://www.w3.org/2001/04/xmlenc#sha256";
        String digestAlg = "http://www.w3.org/2000/09/xmldsig#sha1";
        XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());

        List<Transform> transforms = new ArrayList<Transform>();
        Transform enveloped = xmlSignatureFactory.newTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE, (XMLStructure) null);
        transforms.add(enveloped);
        Transform c14n = xmlSignatureFactory.newTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (XMLStructure) null);
        transforms.add(c14n);

        Reference ref;
        try {
            ref = xmlSignatureFactory.newReference("#" + id, xmlSignatureFactory.newDigestMethod(digestAlg, null), transforms, null, null);
        } catch (NoSuchAlgorithmException e) {
            ref = xmlSignatureFactory.newReference("#" + id, xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null), transforms, null, null);
        }

        KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
        ArrayList list = new ArrayList();
        if (public_key != null) {
            // RSA Injection
            list.add(keyInfoFactory.newKeyValue(public_key));
            signAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        } else {
            // EncryptedKey Injection
            list.add(keyInfoFactory.newKeyName("foo"));
            signAlg = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
        }
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(list);

        SignedInfo signedInfo;
        try {
            signedInfo = xmlSignatureFactory.newSignedInfo(xmlSignatureFactory.newCanonicalizationMethod(
                    CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null), xmlSignatureFactory
                    .newSignatureMethod(signAlg, null), Collections.singletonList(ref));
        } catch (NoSuchAlgorithmException e) {
            signedInfo = xmlSignatureFactory.newSignedInfo(xmlSignatureFactory.newCanonicalizationMethod(
                    CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null), xmlSignatureFactory
                    .newSignatureMethod(org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, null), Collections
                    .singletonList(ref));
        }

        Element elementToSign = doc.getElementById(id);

        NodeList issuerList = elementToSign.getElementsByTagNameNS("*", "Issuer");
        Element elementBeforeSignature;

        if (issuerList.getLength() > 0) {
            elementBeforeSignature = (Element) issuerList.item(0);
        } else {
            elementBeforeSignature = elementToSign;
        }

        Element nextElementAfterIssuer = (Element) elementBeforeSignature.getNextSibling();

        DOMSignContext domSignContext = new DOMSignContext(signing_key, elementToSign);
        domSignContext.setDefaultNamespacePrefix("ds");
        domSignContext.setNextSibling(nextElementAfterIssuer);

        javax.xml.crypto.dsig.XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
        signature.sign(domSignContext);
        return doc;
    }

    public static void setIDAttribute(Document document) {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("//*[local-name()='Assertion' and @*[local-name()='ID' or local-name()='id' or local-name()='AssertionID' or local-name()='AssertionId']]");
            NodeList nodeList = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
            for (int i = 0; i < nodeList.getLength(); i++) {
                Element elem = (Element) nodeList.item(i);
                Attr attr = null;
                attr = (Attr) elem.getAttributes().getNamedItem("AssertionID");
                if (attr == null)
                    attr = (Attr) elem.getAttributes().getNamedItem("AssertionId");
                if (attr == null)
                    attr = (Attr) elem.getAttributes().getNamedItem("ID");
                if (attr == null)
                    attr = (Attr) elem.getAttributes().getNamedItem("id");
                if (attr == null)
                    attr = (Attr) elem.getAttributes().getNamedItem("Id");
                if (attr != null)
                elem.setIdAttributeNode(attr, true);
            }
        } catch (XPathExpressionException e) {
            e.printStackTrace(stderr);
        }
    }

    public static NodeList getAssertions(Document document) {
        NodeList nl = document.getElementsByTagNameNS("*", "Assertion");
        return nl;
    }

    public static NodeList getSignatures(Document document) {
        NodeList nl = document.getElementsByTagNameNS("*", "Signature");
        return nl;
    }

    public static int removeAllSignatures(Document document) {
        NodeList nl = getSignatures(document);
        int nrSig = nl.getLength();
        for (int i = 0; i < nrSig; i++) {
            Node parent = nl.item(0).getParentNode();
            parent.removeChild(nl.item(0));
        }
        removeEmptyTags(document);
        document.normalize();
        return nrSig;
    }
    public static String readFile(String path, Charset encoding) throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, encoding);
    }

    public static Document getDocument(String message) throws SAXException {
        try {
            DocumentBuilderFactory documentBuilderFactory = getDBF();
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = documentBuilder.parse(new InputSource(new StringReader(message)));
            return document;
        } catch (ParserConfigurationException e) {
            e.printStackTrace(stderr);
        } catch (IOException e) {
            e.printStackTrace(stderr);
        }
        return null;
    }

    public static DocumentBuilderFactory getDBF() {
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            documentBuilderFactory.setNamespaceAware(true);
            return documentBuilderFactory;
        } catch (ParserConfigurationException e) {
            e.printStackTrace(stderr);
        }
        return null;
    }

    public static String indentXML(String doc) {
        Transformer transformer = null;
        try {
            transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            StreamResult result = new StreamResult(new StringWriter());
            StreamSource source = new StreamSource(new StringReader(doc));
            transformer.transform(source, result);
            String xmlString = result.getWriter().toString();
            xmlString = xmlString.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
            xmlString = xmlString.replaceAll("(?m)^[ \t]*\r?\n", "");
            return xmlString;
        } catch (TransformerConfigurationException e) {
            e.printStackTrace(stderr);
        } catch (TransformerException e) {
            e.printStackTrace(stderr);
        }
        return null;
    }

    public static boolean isValidXML(String message) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilderFactory dbFactory = getDBF();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        StringReader sr = new StringReader(message);
        InputSource is = new InputSource(sr);
        Document document = dBuilder.parse(is);
        return true;
    }
}
