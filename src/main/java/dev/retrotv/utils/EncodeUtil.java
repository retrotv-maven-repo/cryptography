package dev.retrotv.utils;

import dev.retrotv.enums.EncodeFormat;


import lombok.NonNull;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncodeUtil {

    private EncodeUtil() {
        throw new IllegalStateException("유틸리티 클래스 입니다.");
    }

    public static String binaryToHex(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("data는 null일 수 없습니다.");
        }

        return Hex.encodeHexString(data);
    }

    public static String binaryToBase64(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("data는 null일 수 없습니다.");
        }

        return Base64.encodeBase64String(data);
    }

    public static byte[] hexToBinary(@NonNull String hex) throws DecoderException {
        return Hex.decodeHex(hex);
    }

    public static byte[] base64ToBinary(@NonNull String base64) {
        return Base64.decodeBase64(base64);
    }

    public static String binaryEncode(EncodeFormat encodeFormat, byte[] data) {
        if (encodeFormat == null) {
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
