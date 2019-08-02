package helpers;

import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import static burp.BurpExtender.helpers;
import static burp.BurpExtender.stderr;
import static burp.BurpExtender.stdout;

public class EncodingHelper {

    public static boolean isBase64Encoded(String message) {
        String pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";
        Pattern r = Pattern.compile(pattern);
        String string = null;
        Matcher m = r.matcher(message);
        if (m.find()) {
            return true;
        } else {
            return false;
        }
    }

    public static String urldecode(String message) {
        try {
            return URLDecoder.decode(message, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace(stderr);
            return null;
        }
    }

    public static String urlencode(String message) {
        try {
            return URLEncoder.encode(message, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace(stderr);
            return null;
        }
    }

    public static String encodeMessage(String message, List<String> encodings) {


        Collections.reverse(encodings);
        try {
            for (String encoding : encodings) {
                if (encoding.equals("url")) {
                    message = urlencode(message);
                } else if (encoding.equals("base64")) {
                    message = helpers.base64Encode(message);
                } else if (encoding.equals("gzip")) {
                    message = helpers.bytesToString(compress(helpers.stringToBytes(message), true));
                } else if (encoding.equals("inflated")) {
                    message = helpers.bytesToString(compress(helpers.stringToBytes(message), false));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return message;
    }

    public static String decodeMessage(String message, List<String> encodings) {

        // TODO: message should be valid XML, so apply decoders and try to parse it until parsing is valid

        if (message.matches("%[0-9A-Fa-f]{2}") && urldecode(message) != message) {
            encodings.add("url");
            message = urldecode(message);
        }

        byte[] message_bytes;
        if (isBase64Encoded(message)) {
            encodings.add("base64");
            message_bytes = helpers.base64Decode(message);
        } else {
            message_bytes = helpers.stringToBytes(message);
        }

        try {
            message_bytes = decompress(message_bytes, true);
            encodings.add("gzip");
        } catch (Exception e) {}

        try {
            message_bytes = decompress(message_bytes, false);
            encodings.add("inflated");
        } catch (Exception e) {}

        return helpers.bytesToString(message_bytes);
    }



    // Source:
    // http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html
    public static byte[] decompress(byte[] data, boolean gzip) throws IOException, DataFormatException {
        Inflater inflater = new Inflater(true);
        inflater.setInput(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();

        inflater.end();

        return output;
    }

    // Source:
    // http://qupera.blogspot.ch/2013/02/howto-compress-and-uncompress-java-byte.html
    public static byte[] compress(byte[] data, boolean gzip) throws IOException {
        Deflater deflater = new Deflater(5,gzip);
        deflater.setInput(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);

        deflater.finish();
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        byte[] output = outputStream.toByteArray();

        deflater.end();

        return output;
    }
}
