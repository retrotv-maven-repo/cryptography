package dev.retrotv.crypt;

import dev.retrotv.util.CommonMessage;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Encode {
    private static final Logger logger = LogManager.getLogger();

    private static final CommonMessage commonMessage = new CommonMessage();

    public static String binaryToHex(byte[] data) {
        if (data == null) {
            logger.error(commonMessage.getMessage("error.parameter.null", "data"));
            throw new NullPointerException(commonMessage.getMessage("exception.nullPointer", "data"));
        }

        return Hex.encodeHexString(data);
    }

    public static String binaryToBase64(byte[] data) {
        if (data == null) {
            logger.error(commonMessage.getMessage("error.parameter.null", "data"));
            throw new NullPointerException(commonMessage.getMessage("exception.nullPointer", "data"));
        }

        return Base64.encodeBase64String(data);
    }

    public static byte[] hexToBinary(String hex) throws DecoderException {
        if (hex == null) {
            logger.error(commonMessage.getMessage("error.parameter.null", "hex"));
            throw new NullPointerException(commonMessage.getMessage("exception.nullPointer", "hex"));
        }

        return Hex.decodeHex(hex);
    }

    public static byte[] base64ToBinary(String base64) {
        if (base64 == null) {
            logger.error(commonMessage.getMessage("error.parameter.null", "base64"));
            throw new NullPointerException(commonMessage.getMessage("exception.nullPointer", "base64"));
        }

        return Base64.decodeBase64(base64);
    }

    public static String binaryEncode(EncodeFormat encodeFormat, byte[] data) {
        if (encodeFormat == null) {
            logger.warn("인코딩 방식이 지정되지 않았습니다. 기본 설정인 Hex 방식으로 인코딩 됩니다.");
            encodeFormat = EncodeFormat.HEX;
        }

        if (data == null) {
            logger.error(commonMessage.getMessage("error.parameter.null", "data"));
            throw new NullPointerException(commonMessage.getMessage("exception.nullPointer", "data"));
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
