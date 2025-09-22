package dev.retrotv.crypto.password.scrypt;

import dev.retrotv.crypto.password.PasswordEncoder;

/**
 * SCrypt 해싱 함수를 사용하는 PasswordEncoder 구현.
 * SCryptPasswordEncoder는 CPU 비용, 메모리 비용, 병렬화, 키 길이 및 솔트 길이 매개변수를 제공할 수 있습니다.
 */
public class SCryptPasswordEncoder implements PasswordEncoder {
    private final org.springframework.security.crypto.scrypt.SCryptPasswordEncoder encoder;

    /**
     * 기본 SCryptPasswordEncoder를 생성합니다.
     */
    public SCryptPasswordEncoder() {
        this.encoder = new org.springframework.security.crypto.scrypt.SCryptPasswordEncoder(65536, 8, 1, 32, 64);
    }

    /**
     * 주어진 매개변수를 사용하여 SCryptPasswordEncoder를 생성합니다.
     *
     * @param cpuCost CPU 비용 (scrypt에서 N으로 정의됨). 1보다 큰 2의 거듭제곱이어야 합니다. 기본값은 현재 65,536 또는 2^16입니다.
     * @param memoryCost 메모리 비용 (scrypt에서 r로 정의됨). 기본값은 현재 8입니다.
     * @param parallelization 병렬화 (scrypt에서 p로 정의됨). 기본값은 현재 1입니다. 구현은 현재 병렬화를 활용하지 않습니다.
     * @param keyLength 키 길이 (scrypt에서 dkLen으로 정의됨). 기본값은 현재 32입니다.
     * @param saltLength 솔트 길이 (scrypt에서 S의 길이로 정의됨). 기본값은 현재 16입니다.
     */
    public SCryptPasswordEncoder(int cpuCost, int memoryCost, int parallelization, int keyLength, int saltLength) {
        this.encoder = new org.springframework.security.crypto.scrypt.SCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength);
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

