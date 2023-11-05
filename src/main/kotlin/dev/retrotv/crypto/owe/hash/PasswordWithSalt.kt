package dev.retrotv.crypto.owe.hash

import dev.retrotv.utils.PasswordStrengthUtil
import org.springframework.security.crypto.password.PasswordEncoder
import java.nio.charset.Charset

/**
 * 소금을 이용한 패스워드 암호화 클래스 구현을 위한 인터페이스 입니다.
 * [PasswordEncoder]를 상속받습니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
interface PasswordWithSalt : PasswordEncoder {
    override fun encode(rawPassword: CharSequence): String

    /**
     * 패스워드를 암호화 한 뒤, 암호화 된 패스워드를 지정된 캐릭터 셋으로 변환한 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @return 암호화 된 패스워드 문자열
     */
    fun encode(rawPassword: CharSequence, charset: Charset): String

    /**
     * 패스워드에 소금을 치고 암호화 한 뒤, 암호화 된 패스워드 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @return 암호화 된 패스워드 문자열
     */
    fun encode(rawPassword: CharSequence, salt: CharSequence): String

    /**
     * 패스워드에 소금을 치고 암호화 한 뒤, 암호화 된 패스워드 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @param charset 인코딩 시 사용할 문자열 셋
     * @return 암호화 된 패스워드 문자열
     */
    fun encode(rawPassword: CharSequence, salt: CharSequence, charset: Charset): String

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean

    /**
     * 패스워드에 소금을 치고 암호화 된 문자열을 비교할 암호화 된 문자열과 비교 후, 일치 여부를 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @param encodedPassword 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    fun matches(rawPassword: CharSequence, salt: CharSequence, encodedPassword: String?): Boolean

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
