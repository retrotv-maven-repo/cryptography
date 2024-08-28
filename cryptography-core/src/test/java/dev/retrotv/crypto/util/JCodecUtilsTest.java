package dev.retrotv.crypto.util;

import dev.retrotv.data.enums.EncodeFormat;
import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static dev.retrotv.data.enums.EncodeFormat.BASE64;
import static dev.retrotv.data.enums.EncodeFormat.HEX;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class JCodecUtilsTest {

    @Nested
    @DisplayName("encode 메소드 테스트")
    class EncodeMethodTestClass {

        @Test
        @DisplayName("HEX 인코딩 테스트")
        void testHexEncode() {
            byte[] bytes = new byte[]{1, 2, 3, 4};
            String encoded = CodecUtils.encode(bytes, EncodeFormat.HEX);
            assertEquals("01020304", encoded);
        }

        @Test
        @DisplayName("BASE64 인코딩 테스트")
        void testBase64Encode() {
            byte[] bytes = new byte[]{1, 2, 3, 4};
            String encoded = CodecUtils.encode(bytes, BASE64);
            assertEquals("AQIDBA==", encoded);

            encoded = CodecUtils.encode(bytes);
            assertEquals("AQIDBA==", encoded);
        }
    }

    @Nested
    @DisplayName("decode 메소드 테스트")
    class DecodeMethodTestClass {

        @Test
        @DisplayName("HEX 디코딩 테스트")
        void testHexDecode() throws DecoderException {
            String encoded = "01020304";
            byte[] decoded = CodecUtils.decode(encoded, HEX);
            assertArrayEquals(new byte[]{1, 2, 3, 4}, decoded);
        }

        @Test
        @DisplayName("BASE64 디코딩 테스트")
        void testBase64Decode() throws DecoderException {
            String encoded = "AQIDBA==";
            byte[] decoded = CodecUtils.decode(encoded, BASE64);
            assertArrayEquals(new byte[]{1, 2, 3, 4}, decoded);

            decoded = CodecUtils.decode(encoded);
            assertArrayEquals(new byte[]{1, 2, 3, 4}, decoded);
        }
    }
}
