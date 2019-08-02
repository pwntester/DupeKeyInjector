package application;

import java.util.List;

public class SAMLMessage {

    private byte[] originalRequest;
    private String message;
    private String slotName;
    private byte slotType;
    private List<String> encodings;

    public byte getSlotType() {
        return slotType;
    }

    public void setSlotType(byte slotType) {
        this.slotType = slotType;
    }

    public List<String> getEncodings() {
        return encodings;
    }

    public void setEncodings(List<String> encodings) {
        this.encodings = encodings;
    }

    public String getSlotName() {
        return slotName;
    }

    public void setSlotName(String slotName) {
        this.slotName = slotName;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public byte[] getOriginalRequest() {
        return originalRequest;
    }

    public void setOriginalRequest(byte[] originalRequest) {
        this.originalRequest = originalRequest;
    }

    public SAMLMessage(byte[] originalRequest) {
        this.originalRequest = originalRequest;
    }
}
