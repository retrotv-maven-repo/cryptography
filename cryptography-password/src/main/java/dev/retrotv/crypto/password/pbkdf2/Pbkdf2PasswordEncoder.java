package dev.retrotv.crypto.password.pbkdf2;

import dev.retrotv.crypto.password.PasswordEncoder;
import dev.retrotv.crypto.password.enums.SecretKeyFactoryAlgorithm;

/**
 * Pbkdf2 해싱 함수를 사용하는 PasswordEncoder 구현.
 * 클라이언트는 선택적으로 사용할 비밀 값, salt의 길이, 반복 횟수 및 사용할 알고리즘을 제공할 수 있습니다.
 */
public class Pbkdf2PasswordEncoder implements PasswordEncoder {
    private final org.springframework.security.crypto.password.Pbkdf2PasswordEncoder encoder;

    /**
     * 기본 Pbkdf2PasswordEncoder를 생성합니다.
     */
    public Pbkdf2PasswordEncoder() {
        this.encoder = new org.springframework.security.crypto.password.Pbkdf2PasswordEncoder("", 16, 310000, selectSecretKeyFactoryAlgorithm(SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256));
    }

    /**
     * 주어진 매개변수를 사용하여 Pbkdf2PasswordEncoder를 생성합니다.
     * @param secret 비밀 값
     * @param saltLength 솔트 길이 (바이트 단위)
     * @param iterations 반복 횟수. 사용자는 자신의 시스템에서 약 0.5초가 걸리도록 설정해야 합니다.
     * @param secretKeyFactoryAlgorithm 사용할 알고리즘
     */
    public Pbkdf2PasswordEncoder(CharSequence secret, int saltLength, int iterations, SecretKeyFactoryAlgorithm secretKeyFactoryAlgorithm) {
        this.encoder = new org.springframework.security.crypto.password.Pbkdf2PasswordEncoder(
            secret.toString(), saltLength, iterations, selectSecretKeyFactoryAlgorithm(secretKeyFactoryAlgorithm)
        );
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return this.encoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return this.encoder.matches(rawPassword, encodedPassword);
    }

    private org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm selectSecretKeyFactoryAlgorithm(SecretKeyFactoryAlgorithm secretKeyFactoryAlgorithm) {
        switch (secretKeyFactoryAlgorithm) {
            case PBKDF2WithHmacSHA1:
                return org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA1;
            case PBKDF2WithHmacSHA256:
                return org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256;
            case PBKDF2WithHmacSHA512:
                return org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA512;
            default:
                throw new IllegalArgumentException("Unknown SecretKeyFactoryAlgorithm: " + secretKeyFactoryAlgorithm);
        }
    }
}
