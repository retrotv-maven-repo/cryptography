package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.random.SecurityStrength;

public interface PasswordWithSalt extends Password {

    /**
     *
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @return 암호화 된 문자열
     */
    default String encode(CharSequence rawPassword, CharSequence salt) {
        return encode(String.join(rawPassword, salt));
    }

    /**
     *
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
     *
     *
     * @return 생성된 소금
     */
    default String generateSalt() {
        return RandomValue.generate();
    }

    /**
     *
     *
     * @param length 생성할 소금의 길이
     * @return 생성된 소금
     */
    default String generateSalt(int length) {
        return RandomValue.generate(length);
    }

    /**
     *
     *
     * @param securityStrength 보안 강도, {@link SecurityStrength} 참조
     * @return 생성된 소금
     */
    default String generateSalt(SecurityStrength securityStrength) {
        return RandomValue.generate(securityStrength);
    }

    /**
     *
     *
     * @param securityStrength 보안 강도, {@link SecurityStrength} 참조
     * @param length 생성할 소금의 길이
     * @return 생성된 소금
     */
    default String generateSalt(SecurityStrength securityStrength, int length) {
        return RandomValue.generate(securityStrength, length);
    }
}
