package dev.retrotv.crypto.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class Base64CodecUtilsTest {

    @Test
    @DisplayName("encode param not null 테스트")
    void test_encodeParamNotNull() {
        assertThrows(NullPointerException.class, () -> Base64CodecUtils.encode(null));
    }
}
