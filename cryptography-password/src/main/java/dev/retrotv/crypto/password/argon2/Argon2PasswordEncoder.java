package dev.retrotv.crypto.password.argon2;

import dev.retrotv.crypto.password.PasswordEncoder;

/**
 * Argon2 해싱 함수를 사용하는 PasswordEncoder 구현.
 * 클라이언트는 선택적으로 사용할 salt의 길이, 생성된 해시의 길이, CPU 비용 매개변수, 메모리 비용 매개변수 및 병렬화 매개변수를 제공할 수 있습니다.
 */
public class Argon2PasswordEncoder implements PasswordEncoder {
    private final org.springframework.security.crypto.argon2.Argon2PasswordEncoder encoder;

    /**
     * 기본 Argon2PasswordEncoder를 생성합니다.
     */
    public Argon2PasswordEncoder() {
        this.encoder = new org.springframework.security.crypto.argon2.Argon2PasswordEncoder(16, 32, 1, 16384, 2);
    }

    /**
     * 주어진 매개변수를 사용하여 Argon2PasswordEncoder를 생성합니다.
     *
     * @param saltLength salt의 길이 (바이트 단위)
     * @param hashLength 해시의 길이 (바이트 단위)
     * @param parallelism 병렬 처리 수
     * @param memory 메모리 비용
     * @param iterations 반복 횟수
     */
    public Argon2PasswordEncoder(int saltLength, int hashLength, int parallelism, int memory, int iterations) {
        this.encoder = new org.springframework.security.crypto.argon2.Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return this.encoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return this.encoder.matches(rawPassword, encodedPassword);
    }
}

