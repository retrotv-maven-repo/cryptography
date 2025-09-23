package dev.retrotv.crypto.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class Base64CodecUtilsTest {

    @Test
    @DisplayName("encode param not null 테스트")
    void test_encodeParamNotNull() {
        assertThrows(NullPointerException.class, () -> Base64CodecUtils.encode(null));

        try {
            Base64CodecUtils.encode(null);
        } catch (NullPointerException ex) {
            assert ex.getMessage().equals("인코딩할 바이트 배열은 null일 수 없습니다.");
        }
    }
}
