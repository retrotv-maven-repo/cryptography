package dev.retrotv.crypto.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;

import java.security.SecureRandom;
import java.util.regex.Pattern;

import static dev.retrotv.random.enums.SecurityStrength.MIDDLE;
import static org.junit.jupiter.api.Assertions.*;

class JRandomGenerateUtilsTest {

    @RepeatedTest(value = 100, name = "{displayName} - {currentRepetition}/{totalRepetitions}")
    @DisplayName("generateBytes() 메소드 테스트")
    void test_generateBytes_method() {
        byte[] bytes = RandomGenerateUtils.generateBytes();
        assertNotNull(bytes);
        assertEquals(16, bytes.length);

        bytes = RandomGenerateUtils.generateBytes(16);
        assertNotNull(bytes);
        assertEquals(16, bytes.length);

        bytes = RandomGenerateUtils.generateBytes(16, new SecureRandom());
        assertNotNull(bytes);
        assertEquals(16, bytes.length);
    }

    @RepeatedTest(value = 100, name = "{displayName} - {currentRepetition}/{totalRepetitions}")
    @DisplayName("generateString() 메소드 테스트")
    void test_generateString_method() {
        String str = RandomGenerateUtils.generateString();
        assertNotNull(str);
        assertEquals(16, str.length());

        str = RandomGenerateUtils.generateString(16);
        assertNotNull(str);
        assertEquals(16, str.length());

        str = RandomGenerateUtils.generateString(16, MIDDLE);
        assertNotNull(str);
        assertEquals(16, str.length());
        assertTrue(Pattern.compile(".*[A-Z]+").matcher(str).find());
        assertTrue(Pattern.compile(".*[a-z]+").matcher(str).find());
        assertTrue(Pattern.compile(".*[0-9]+").matcher(str).find());
        assertFalse(Pattern.compile(".*[^A-Za-z0-9]+").matcher(str).find());

        str = RandomGenerateUtils.generateString(16, MIDDLE, new SecureRandom());
        assertNotNull(str);
        assertEquals(16, str.length());
        assertTrue(Pattern.compile(".*[A-Z]+").matcher(str).find());
        assertTrue(Pattern.compile(".*[a-z]+").matcher(str).find());
        assertTrue(Pattern.compile(".*[0-9]+").matcher(str).find());
        assertFalse(Pattern.compile(".*[^A-Za-z0-9]+").matcher(str).find());
    }
}
