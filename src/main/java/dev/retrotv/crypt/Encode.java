package dev.retrotv.crypt;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Encode {
    private static final Logger logger = LogManager.getLogger();

    public static String binaryToHex(byte[] data) {
        if (data == null) {
            logger.error("인코딩 할 데이터가 null 입니다.");
            throw new NullPointerException("매개변수 data가 null 입니다.");
        }

        return Hex.encodeHexString(data);
    }

    public static String binaryToBase64(byte[] data) {
        if (data == null) {
            logger.error("인코딩 할 데이터가 null 입니다.");
            throw new NullPointerException("매개변수 data가 null 입니다.");
        }

        return Base64.encodeBase64String(data);
    }

    public static byte[] hexToBinary(String hex) throws DecoderException {
        if (hex == null) {
            logger.error("디코딩 할 문자열이 null 입니다.");
            throw new NullPointerException("매개변수 hex가 null 입니다.");
        }

        return Hex.decodeHex(hex);
    }

    public static byte[] base64ToBinary(String base64) {
        if (base64 == null) {
            logger.error("디코딩 할 문자열이 null 입니다.");
            throw new NullPointerException("매개변수 base64가 null 입니다.");
        }

        return Base64.decodeBase64(base64);
    }

    public static String binaryEncode(EncodeFormat encodeFormat, byte[] data) {
        if (encodeFormat == null) {
            logger.warn("인코딩 방식이 지정되지 않았습니다. 기본 설정인 Hex 방식으로 인코딩 됩니다.");
            encodeFormat = EncodeFormat.HEX;
        }

        if (data == null) {
            logger.error("인코딩할 데이터가 존재하지 않습니다.");
            throw new NullPointerException("매개변수 data가 null 입니다.");
        }

        switch (encodeFormat) {
            case BASE64:
                return binaryToBase64(data);

            case HEX:
            default:
                return binaryToHex(data);
        }
    }
}
