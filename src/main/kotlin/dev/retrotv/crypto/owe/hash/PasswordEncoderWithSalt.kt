package dev.retrotv.crypto.owe.hash

import dev.retrotv.crypto.exception.SaltGenerateException
import dev.retrotv.random.PasswordGenerator
import dev.retrotv.random.RandomStringGenerator
import dev.retrotv.random.enums.SecurityStrength
import dev.retrotv.utils.getMessage
import org.springframework.security.crypto.password.PasswordEncoder
import java.nio.charset.Charset

/**
 * 소금을 이용한 패스워드 암호화 클래스 구현을 위한 인터페이스 입니다.
 * [PasswordEncoder]를 상속받습니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
interface PasswordEncoderWithSalt : PasswordEncoder, PlaintextHash {

    private companion object {
        val SALT_GENERATE_EXCEPTION = getMessage("exception.saltGenerate")
    }

    /**
     * 패스워드를 암호화 한 뒤, 암호화 된 패스워드를 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @return 암호화 된 패스워드 문자열
     */
    override fun encode(rawPassword: CharSequence): String = hash(rawPassword)

    /**
     * 패스워드를 암호화 한 뒤, 암호화 된 패스워드를 지정된 캐릭터 셋으로 변환한 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param charset 인코딩 시 사용할 문자열 셋
     * @return 암호화 된 패스워드 문자열
     */
    fun encode(rawPassword: CharSequence, charset: Charset): String = hash(rawPassword, charset)

    /**
     * 패스워드에 소금을 치고 암호화 한 뒤, 암호화 된 패스워드 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @return 암호화 된 패스워드 문자열
     */
    fun encode(rawPassword: CharSequence, salt: CharSequence): String {
        return encode(rawPassword.toString() + salt)
    }

    /**
     * 패스워드에 소금을 치고 암호화 한 뒤, 암호화 된 패스워드 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @param charset 인코딩 시 사용할 문자열 셋
     * @return 암호화 된 패스워드 문자열
     */
    fun encode(rawPassword: CharSequence, salt: CharSequence, charset: Charset): String {
        return encode(rawPassword.toString() + salt, charset)
    }

    /**
     * 패스워드를 암호화하고 비교할 암호화 된 문자열과 비교 후, 일치 여부를 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param encodedPassword 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return if (encodedPassword == null) {
            false
        } else  encodedPassword == encode(rawPassword)
    }

    /**
     * 패스워드에 소금을 치고 암호화 된 문자열을 비교할 암호화 된 문자열과 비교 후, 일치 여부를 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @param encodedPassword 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    fun matches(rawPassword: CharSequence, salt: CharSequence, encodedPassword: String?): Boolean {
        return if (encodedPassword == null) {
            false
        } else matches(
            rawPassword.toString() + salt,
            encodedPassword
        )
    }

    /**
     * 소금을 생성하고 반환합니다.
     * 보안 강도와 소금의 길이는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @return 생성된 소금
     */
    fun generateSalt(): String {
        val rv: RandomStringGenerator = PasswordGenerator(SecurityStrength.MIDDLE)
        rv.generate(16)
        return rv.getString() ?: throw SaltGenerateException(SALT_GENERATE_EXCEPTION)
    }

    /**
     * len 만큼의 길이를 가진 소금을 생성하고 반환합니다.
     * 보안 강도는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @param len 생성할 소금의 길이
     * @return 생성된 소금
     */
    fun generateSalt(len: Int): String {
        val rv: RandomStringGenerator = PasswordGenerator(SecurityStrength.MIDDLE)
        rv.generate(len)
        return rv.getString() ?: throw SaltGenerateException(SALT_GENERATE_EXCEPTION)
    }

    /**
     * securityStrength 수준의 소금을 생성하고 반환합니다.
     * 소금의 길이는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @param securityStrength 보안 강도, [SecurityStrength] 참조
     * @return 생성된 소금
     */
    fun generateSalt(securityStrength: SecurityStrength): String {
        val rv: RandomStringGenerator = PasswordGenerator(securityStrength)
        rv.generate(16)
        return rv.getString() ?: throw SaltGenerateException(SALT_GENERATE_EXCEPTION)
    }

    /**
     * securityStrength의 수준과 len 만큼의 길이를 가진 소금을 생성하고 반환합니다.
     *
     * @param len 생성할 소금의 길이
     * @param securityStrength 보안 강도, [SecurityStrength] 참조
     * @return 생성된 소금
     */
    fun generateSalt(len: Int, securityStrength: SecurityStrength): String {
        val rv: RandomStringGenerator = PasswordGenerator(securityStrength)
        rv.generate(len)
        return rv.getString() ?: throw SaltGenerateException(SALT_GENERATE_EXCEPTION)
    }

    /**
     * 더 나은 보안을 위해 인코딩된 비밀번호를 다시 인코딩해야 하는 경우 true를 반환하고,
     * 그렇지 않으면 false를 반환합니다. 기본 구현은 항상 false를 반환합니다.
     *
     * @param encodedPassword 암호화 된 문자열
     */
    override fun upgradeEncoding(encodedPassword: String?): Boolean {
        return false
    }
}
