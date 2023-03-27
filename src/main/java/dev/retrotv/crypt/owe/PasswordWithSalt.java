package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.random.SecurityStrength;

public interface PasswordWithSalt extends Password {

    /**
     *
     * @param rawPassword
     * @param salt
     * @return
     */
    default String encode(CharSequence rawPassword, CharSequence salt) {
        return encode(String.join(rawPassword, salt));
    }

    /**
     *
     * @param rawPassword
     * @param salt
     * @param encodedPassword
     * @return
     */
    default boolean matches(CharSequence rawPassword, CharSequence salt, String encodedPassword) {
        if (rawPassword == null || salt == null || encodedPassword == null) {
            throw new NullPointerException("비교할 password, salt 혹은 encodedPassword 값이 null 입니다.");
        }

        return matches(String.join(rawPassword, salt), encodedPassword);
    }

    /**
     *
     * @return
     */
    default String generateSalt() {
        return RandomValue.generate();
    }

    /**
     *
     * @param length
     * @return
     */
    default String generateSalt(int length) {
        return RandomValue.generate(length);
    }

    /**
     *
     * @param securityStrength
     * @return
     */
    default String generateSalt(SecurityStrength securityStrength) {
        return RandomValue.generate(securityStrength);
    }

    /**
     *
     * @param securityStrength
     * @param length
     * @return
     */
    default String generateSalt(SecurityStrength securityStrength, int length) {
        return RandomValue.generate(securityStrength, length);
    }
}
