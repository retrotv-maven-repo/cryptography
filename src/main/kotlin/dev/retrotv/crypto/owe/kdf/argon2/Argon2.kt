package dev.retrotv.crypto.owe.kdf.argon2

import dev.retrotv.crypto.owe.kdf.KDF
import dev.retrotv.utils.PasswordStrengthUtil
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder

/**
 * Argon2 알고리즘으로 암호화 하기 위한 [KDF] 추상 클래스의 구현체 입니다.
 * Spring Security의 [PasswordEncoder]와 호환됩니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class Argon2 : KDF {
    private val argon2PasswordEncoder: Argon2PasswordEncoder

    /**
     * [Argon2PasswordEncoder] 인스턴스를 초기화 합니다.<br></br>
     * 이 때, Argon2 암호화 알고리즘의 기본 설정을 사용합니다.<br></br>
     * <br></br>
     * **!Argon2 기본 설정**<br></br>
     * saltLength: 16<br></br>
     * hashLength: 32<br></br>
     * parallelism: 1<br></br>
     * memory 1 &lt;&lt; 14<br></br>
     * interations 2<br></br>
     */
    constructor() {
        argon2PasswordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
    }

    /**
     * [Argon2PasswordEncoder] 인스턴스를 초기화 합니다.<br></br>
     * <br></br>
     * **!매개변수 권장 값**<br></br>
     * saltLength: 16<br></br>
     * hashLength: 32 혹은 16<br></br>
     * parallelism: CPU Core 수의 두 배<br></br>
     * memory 1 &lt;&lt; 14 이상<br></br>
     * iterations 2 이상<br></br>
     * <br></br>
     * 공간상의 제약이 없다면 saltLength는 16, hashLength는 32로 하는 것을 권장합니다.<br></br>
     * 만약 공간상의 제약이 있다면, hashLength를 16으로 낮추는 것을 고려하십시오.<br></br>
     * <br></br>
     * 암호화하는 데 걸리는 시간을 조정하려면 memory와 interation 값을 조금씩 높여보면서 테스트 하십시오.<br></br>
     * 암호화하는 데 걸리는 시간이 길수록 안전하지만, 서비스 이용에 불편함이 생길 수 있으니 편의와 보안 간의 균형을 맞추십시오.<br></br>
     *
     * @param saltLength 소금의 길이 (bytes 단위)
     * @param hashLength 해시 결과물의 길이 (bytes 단위)
     * @param parallelism 스레드 개수 (클수록 안전함)
     * @param memory 암호화 시, 연산에 사용할 메모리의 크기 (클수록 안전함)
     * @param iterations 메모리에 대한 연산 반복 횟수 (클수록 안전함)
     */
    constructor(saltLength: Int, hashLength: Int, parallelism: Int, memory: Int, iterations: Int) {
        argon2PasswordEncoder = Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return if (encodedPassword == null) {
            false
        } else argon2PasswordEncoder.matches(rawPassword, encodedPassword)
    }

    override fun encode(rawPassword: CharSequence): String {
        return argon2PasswordEncoder.encode(rawPassword)
    }

    override fun upgradeEncoding(encodedPassword: String?): Boolean {
        return if (encodedPassword == null) {
            false
        } else PasswordStrengthUtil.checkLength(8, encodedPassword) &&
                PasswordStrengthUtil.isInclude(
                    true,
                    false,
                    false,
                    true,
                    true,
                    encodedPassword
                )
    }
}
