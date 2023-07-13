package dev.retrotv.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.SecureRandom;

public class SecureRandomUtil {
    private static final Logger log = LogManager.getLogger();

    private SecureRandomUtil() {
        throw new IllegalStateException("유틸리티 클래스 입니다.");
    }

    public static byte[] generate(int len) {
        log.debug("랜덤 값 byte 길이: {}", len);

        SecureRandom sr = new SecureRandom();
        byte[] randomData = new byte[len];
        sr.nextBytes(randomData);

        return randomData;
    }
}
