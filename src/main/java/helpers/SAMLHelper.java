package helpers;

import application.SAMLMessage;
import burp.IParameter;
import burp.IRequestInfo;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import static burp.BurpExtender.helpers;
import static helpers.EncodingHelper.decodeMessage;

public class SAMLHelper {
    public static SAMLMessage getSAMLMessage(byte[] content) {
        SAMLMessage message = new SAMLMessage(content);
        IRequestInfo requestInfo = helpers.analyzeRequest(content);
        // SOAP Message
        if (requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_XML) {
            int bodyOffset = requestInfo.getBodyOffset();
            String body = null;
            try {
                body = new String(content, bodyOffset, content.length - bodyOffset, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            //byte[] body =  Arrays.copyOfRange(content, bodyOffset, content.length - bodyOffset);
            message.setSlotName("body");
            message.setSlotType(IParameter.PARAM_BODY);
            List<String> encodings = new ArrayList<String>();
            String decoded = decodeMessage(body, encodings);
            message.setMessage(decoded);
            message.setEncodings(encodings);
            return message;
        }
        // WSS Security
        else if (null != helpers.getRequestParameter(content, "wresult")) {
            IParameter parameter = helpers.getRequestParameter(content, "wresult");
            message.setSlotName(parameter.getName());
            message.setSlotType(parameter.getType());
            List<String> encodings = new ArrayList<String>();
            String decoded = decodeMessage(parameter.getValue(), encodings);
            message.setMessage(decoded);
            message.setEncodings(encodings);
            return message;
        } else if (null != helpers.getRequestParameter(content, "SAMLResponse")) {
            IParameter parameter = helpers.getRequestParameter(content, "SAMLResponse");
            message.setSlotName(parameter.getName());
            message.setSlotType(parameter.getType());
            List<String> encodings = new ArrayList<String>();
            String decoded = decodeMessage(parameter.getValue(), encodings);
            message.setMessage(decoded);
            message.setEncodings(encodings);
            return message;
        } else if (null != helpers.getRequestParameter(content, "SAMLRequest")) {
            IParameter parameter = helpers.getRequestParameter(content, "SAMLRequest");
            message.setSlotName(parameter.getName());
            message.setSlotType(parameter.getType());
            List<String> encodings = new ArrayList<String>();
            String decoded = decodeMessage(parameter.getValue(), encodings);
            message.setMessage(decoded);
            message.setEncodings(encodings);
            return message;
        }
        return null;
    }
}
