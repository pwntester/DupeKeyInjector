package helpers;

import org.apache.xml.security.signature.XMLSignature;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.util.Iterator;

public class RSAKeySelector extends KeySelector {
    public KeySelectorResult select(KeyInfo keyInfo,
                                    Purpose purpose,
                                    AlgorithmMethod method,
                                    XMLCryptoContext context) throws KeySelectorException {
        @SuppressWarnings("rawtypes")
        Iterator ki = keyInfo.getContent().iterator();
        while (ki.hasNext()) {
            XMLStructure info = (XMLStructure) ki.next();
            if (!(info instanceof KeyValue))
                continue;
            KeyValue RSAData = (KeyValue) info;
            try {
                PublicKey key = RSAData.getPublicKey();
                // Make sure the algorithm is compatible
                // with the method.
                if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                    return new KeySelectorResult() {
                        public Key getKey() { return key; }
                    };
                }
            } catch (KeyException e) {
                e.printStackTrace();
            }
        }
        throw new KeySelectorException("No key found!");
    }

    static boolean algEquals(String algURI, String algName) {
        if ((algName.equalsIgnoreCase("DSA") &&
                algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) ||
                (algName.equalsIgnoreCase("RSA") &&
                        algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) ||
                (algName.equalsIgnoreCase("RSA") &&
                        algURI.equalsIgnoreCase(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256))){
            return true;
        } else {
            return false;
        }
    }
}
