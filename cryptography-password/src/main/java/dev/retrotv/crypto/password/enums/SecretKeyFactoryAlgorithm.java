package dev.retrotv.crypto.password.enums;

/**
 * Pbkdf2PasswordEncoder에서 사용하는 SecretKeyFactory 알고리즘을 나타내는 열거형 클래스입니다.
 */
@SuppressWarnings("java:S115")
public enum SecretKeyFactoryAlgorithm {
    PBKDF2WithHmacSHA1,
    PBKDF2WithHmacSHA256,
    PBKDF2WithHmacSHA512
}

