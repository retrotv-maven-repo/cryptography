package dev.retrotv.crypto.util;

import java.security.SecureRandom;
import java.util.Random;

import dev.retrotv.random.enums.SecurityStrength;
import dev.retrotv.random.generator.ByteGenerator;
import dev.retrotv.random.generator.PasswordGenerator;

import static dev.retrotv.random.enums.SecurityStrength.MIDDLE;

/**
 * 무작위 값을 생성하는 유틸리티 클래스입니다.
 *
 * @author yjj8353
 * @since 1.0.0
 */
public class RandomGenerateUtils {
    private RandomGenerateUtils() {
        throw new UnsupportedOperationException("RandomGenerateUtils 클래스는 인스턴스화할 수 없습니다.");
    }

    /**
     * 지정된 길이의 무작위 바이트 배열을 생성합니다.
     *
     * @param length 생성할 바이트 배열의 길이
     * @return 생성된 무작위 바이트 배열
     * @throws IllegalArgumentException 길이가 0 이하인 경우
     */
    public static byte[] generateBytes(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("size는 0보다 커야 합니다.");
        }

        return generateBytes(length, null);
    }

    /**
     * 지정된 길이의 무작위 바이트 배열을 생성합니다.
     *
     * @param length 생성할 바이트 배열의 길이
     * @param random Random 객체 (null인 경우 SecureRandom 사용, java.util.Random 참조)
     * @return 생성된 무작위 바이트 배열
     * @throws IllegalArgumentException 길이가 0 이하인 경우
     */
    public static byte[] generateBytes(int length, Random random) {
        if (random == null) {
            random = new SecureRandom();
        }

        ByteGenerator generator = new ByteGenerator(random);
        generator.setLength(length);

        return generator.generate();
    }

    /**
     * 지정된 길이의 무작위 문자열을 생성합니다.
     *
     * @param length 생성할 문자열의 길이
     * @return 생성된 무작위 문자열
     * @throws IllegalArgumentException 길이가 0 이하인 경우
     */
    public static String generateString(int length) {
        return generateString(length, null);
    }

    /**
     * 지정된 길이와 보안 강도의 무작위 문자열을 생성합니다.
     *
     * @param length           생성할 문자열의 길이
     * @param securityStrength 보안 강도 (null인 경우 MIDDLE 사용, dev.retrotv.random.enums.SecurityStrength 참조)
     * @return 생성된 무작위 문자열
     * @throws IllegalArgumentException length가 0 이하인 경우
     */
    public static String generateString(int length, SecurityStrength securityStrength) {
        return generateString(length, securityStrength, null);
    }

    /**
     * 지정된 길이, 보안 강도 및 Random 객체를 사용하여 무작위 문자열을 생성합니다.
     *
     * @param length           생성할 문자열의 길이
     * @param securityStrength 보안 강도 (null인 경우 MIDDLE 사용, dev.retrotv.random.enums.SecurityStrength 참조)
     * @param random           Random 객체 (null인 경우 SecureRandom 사용, java.util.Random 참조)
     * @return 생성된 무작위 문자열
     */
    public static String generateString(int length, SecurityStrength securityStrength, Random random) {
        if (length <= 0) {
            throw new IllegalArgumentException("length는 0보다 커야 합니다.");
        }

        if (securityStrength == null) {
            securityStrength = MIDDLE;
        }

        if (random == null) {
            random = new SecureRandom();
        }

        PasswordGenerator generator = new PasswordGenerator(random, securityStrength);
        generator.setLength(length);

        return generator.generate();
    }
}
