package dev.retrotv.crypto.password.argon2

import dev.retrotv.crypto.password.PasswordEncoder
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder

/**
 * Argon2 해싱 함수를 사용하는 PasswordEncoder 구현.
 * 클라이언트는 선택적으로 사용할 salt의 길이, 생성된 해시의 길이, CPU 비용 매개변수, 메모리 비용 매개변수 및 병렬화 매개변수를 제공할 수 있습니다.
 */
class Argon2PasswordEncoder : PasswordEncoder {
    private val encoder: Argon2PasswordEncoder

    /**
     * 기본 Argon2PasswordEncoder를 생성합니다.
     */
    constructor() {
        this.encoder = Argon2PasswordEncoder(16, 32 , 1, 16384, 2 )
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
    constructor(saltLength: Int, hashLength: Int, parallelism: Int, memory: Int, iterations: Int) {
        this.encoder = Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations)
    }

    override fun encode(rawPassword: CharSequence): String {
        return this.encoder.encode(rawPassword)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return this.encoder.matches(rawPassword, encodedPassword)
    }
}