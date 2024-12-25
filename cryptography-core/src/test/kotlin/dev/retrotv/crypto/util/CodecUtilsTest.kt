package dev.retrotv.crypto.util

import dev.retrotv.data.enums.EncodeFormat.BASE64
import dev.retrotv.data.enums.EncodeFormat.HEX
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import kotlin.test.Test

class CodecUtilsTest {

    @Nested
    @DisplayName("encode 메소드 테스트")
    inner class EncodeMethodTestClass {

        @Test
        @DisplayName("HEX 인코딩 테스트")
        fun test_encode_hex() {
            val data = byteArrayOf(0x01, 0x02, 0x03, 0x04)

            val encoded = CodecUtils.encode(data, HEX)
            assertEquals("01020304", encoded)
        }

        @Test
        @DisplayName("BASE64 인코딩 테스트")
        fun test_encode_base64() {
            val data = byteArrayOf(0x01, 0x02, 0x03, 0x04)
            var encoded = CodecUtils.encode(data, BASE64)
            assertEquals("AQIDBA==", encoded)
        }
    }

    @Nested
    @DisplayName("decode 메소드 테스트")
    inner class DecodeMethodTestClass {

        @Test
        @DisplayName("HEX 디코딩 테스트")
        fun test_decode_hex() {
            val encoded = "01020304"
            val decoded = CodecUtils.decode(encoded, HEX)
            assertArrayEquals(byteArrayOf(0x01, 0x02, 0x03, 0x04), decoded)
        }

        @Test
        @DisplayName("BASE64 디코딩 테스트")
        fun test_decode_base64() {
            val encoded = "AQIDBA=="
            var decoded = CodecUtils.decode(encoded, BASE64)
            assertArrayEquals(byteArrayOf(0x01, 0x02, 0x03, 0x04), decoded)
        }
    }
}