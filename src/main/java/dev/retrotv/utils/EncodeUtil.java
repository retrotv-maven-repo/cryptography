package dev.retrotv.utils;

import dev.retrotv.enums.EncodeFormat;
import lombok.NonNull;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncodeUtil {
    private static final Logger log = LogManager.getLogger();

    EncodeUtil() {
        throw new IllegalStateException("유틸리티 클래스 입니다.");
    }

    public static String binaryToHex(@NonNull byte[] data) {
        return Hex.encodeHexString(data);
    }

    public static String binaryToBase64(@NonNull byte[] data) {
        return Base64.encodeBase64String(data);
    }

    public static byte[] hexToBinary(@NonNull String hex) throws DecoderException {
        return Hex.decodeHex(hex);
    }

    public static byte[] base64ToBinary(@NonNull String base64) {
        return Base64.decodeBase64(base64);
    }

    public static String binaryEncode(EncodeFormat encodeFormat, @NonNull byte[] data) {
        if (encodeFormat == null) {
            log.warn("인코딩 방식이 지정되지 않았습니다. 기본 설정인 Hex 방식으로 인코딩 됩니다.");
            encodeFormat = EncodeFormat.HEX;
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
