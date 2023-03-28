package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.random.SecurityStrength;

/**
 * 소금을 이용한 패스워드 암호화 클래스 구현을 위한 인터페이스 입니다.
 * {@link Password}를 상속받습니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public interface PasswordWithSalt extends Password {

    /**
     * 패스워드에 소금을 치고 암호화 한 뒤, 암호화 된 패스워드 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @return 암호화 된 패스워드 문자열
     */
    default String encode(CharSequence rawPassword, CharSequence salt) {
        return encode(String.join(rawPassword, salt));
    }

    /**
     * 패스워드에 소금을 치고 암호화 된 문자열을 비교할 암호화 된 문자열과 비교 후, 일치 여부를 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @param encodedPassword 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    default boolean matches(CharSequence rawPassword, CharSequence salt, String encodedPassword) {
        if (rawPassword == null || salt == null || encodedPassword == null) {
            throw new NullPointerException("비교할 password, salt 혹은 encodedPassword 값이 null 입니다.");
        }

        return matches(String.join(rawPassword, salt), encodedPassword);
    }

    /**
     * 소금을 생성하고 반환합니다.
     * 보안 강도와 소금의 길이는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @return 생성된 소금
     */
    default String generateSalt() {
        return RandomValue.generate();
    }

    /**
     * len 만큼의 길이를 가진 소금을 생성하고 반환합니다.
     * 보안 강도는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @param len 생성할 소금의 길이
     * @return 생성된 소금
     */
    default String generateSalt(int len) {
        return RandomValue.generate(len);
    }

    /**
     * securityStrength 수준의 소금을 생성하고 반환합니다.
     * 소금의 길이는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @param securityStrength 보안 강도, {@link SecurityStrength} 참조
     * @return 생성된 소금
     */
    default String generateSalt(SecurityStrength securityStrength) {
        return RandomValue.generate(securityStrength);
    }

    /**
     * securityStrength의 수준과 len 만큼의 길이를 가진 소금을 생성하고 반환합니다.
     *
     * @param securityStrength 보안 강도, {@link SecurityStrength} 참조
     * @param length 생성할 소금의 길이
     * @return 생성된 소금
     */
    default String generateSalt(SecurityStrength securityStrength, int length) {
        return RandomValue.generate(securityStrength, length);
    }
}
