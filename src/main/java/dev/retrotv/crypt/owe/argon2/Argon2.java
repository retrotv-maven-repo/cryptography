package dev.retrotv.crypt.owe.argon2;

import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

public class Argon2 implements Password {
    private final Argon2PasswordEncoder a2pe;

    /**
     *
     */
    public Argon2() {
        a2pe = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    /**
     *
     * @param saltLength 소금의 길이 (bytes 단위)
     * @param hashLength 해시 결과물의 길이 (bytes 단위)
     * @param parallelism 스레드 개수 (클수록 안전함)
     * @param memory 암호화 시, 연산에 사용할 메모리의 크기 (클수록 안전함)
     * @param iterations 메모리에 대한 연산 반복 횟수 (클수록 안전함)
     */
    public Argon2(int saltLength, int hashLength, int parallelism, int memory, int iterations) {
        a2pe = new Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return a2pe.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return a2pe.matches(rawPassword, encodedPassword);
    }
}
