package dev.retrotv.utils;

import dev.retrotv.enums.EncodeFormat;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncodeUtil {
    private static final Logger log = LogManager.getLogger();
    private static final CommonMessageUtil commonMessageUtil = new CommonMessageUtil();

    public static String binaryToHex(byte[] data) {
        if (data == null) {
            log.error(commonMessageUtil.getMessage("error.parameter.null", "data"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "data"));
        }

        return Hex.encodeHexString(data);
    }

    public static String binaryToBase64(byte[] data) {
        if (data == null) {
            log.error(commonMessageUtil.getMessage("error.parameter.null", "data"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "data"));
        }

        return Base64.encodeBase64String(data);
    }

    public static byte[] hexToBinary(String hex) throws DecoderException {
        if (hex == null) {
            log.error(commonMessageUtil.getMessage("error.parameter.null", "hex"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "hex"));
        }

        return Hex.decodeHex(hex);
    }

    public static byte[] base64ToBinary(String base64) {
        if (base64 == null) {
            log.error(commonMessageUtil.getMessage("error.parameter.null", "base64"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "base64"));
        }

        return Base64.decodeBase64(base64);
    }

    public static String binaryEncode(EncodeFormat encodeFormat, byte[] data) {
        if (encodeFormat == null) {
            log.warn("인코딩 방식이 지정되지 않았습니다. 기본 설정인 Hex 방식으로 인코딩 됩니다.");
            encodeFormat = EncodeFormat.HEX;
        }

        if (data == null) {
            log.error(commonMessageUtil.getMessage("error.parameter.null", "data"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "data"));
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
