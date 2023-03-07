package dev.retrotv.crypt;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class Encode {

    public static String binaryToHex(byte[] data) {
        return Hex.encodeHexString(data);
    }

    public static String binaryToBase64(byte[] data) {
        return Base64.encodeBase64String(data);
    }

    public static byte[] hexToBinary(String hex) throws DecoderException {
        return Hex.decodeHex(hex);
    }

    public static byte[] base64ToBinary(String base64) {
        return Base64.decodeBase64(base64);
    }

    public static String binaryEncode(EncodeFormat encodeFormat, byte[] data) {
        switch (encodeFormat) {
            case BASE64:
                return binaryToBase64(data);

            case HEX:
            default:
                return binaryToHex(data);
        }
    }
}
