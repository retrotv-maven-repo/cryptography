package dev.retrotv.utils;

import java.security.SecureRandom;

public class SecureRandomUtil {

    private SecureRandomUtil() {
        throw new IllegalStateException("유틸리티 클래스 입니다.");
    }

    public static byte[] generate(int len) {
        SecureRandom sr = new SecureRandom();
        byte[] randomData = new byte[len];
        sr.nextBytes(randomData);

        return randomData;
    }
}
