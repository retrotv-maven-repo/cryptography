package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.exception.CryptFailException;
import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.random.SecurityStrength;

public interface PasswordWithSalt extends Password {

    default String encode(CharSequence rawPassword, CharSequence salt) {
        return encode(String.join(rawPassword, salt));
    }

    default boolean matches(CharSequence rawPassword, CharSequence salt, String encodedPassword) {
        if (rawPassword == null || salt == null || encodedPassword == null) {
            throw new CryptFailException("비교할 password, salt 혹은 encodedPassword 값이 null 입니다.");
        }

        return matches(String.join(rawPassword, salt), encodedPassword);
    }

    default String generateSalt() {
        return RandomValue.generate(SecurityStrength.MIDDLE, 16);
    }

    default String generateSalt(int length) {
        return RandomValue.generate(SecurityStrength.MIDDLE, length);
    }

    default String generateSalt(SecurityStrength securityStrength) {
        return RandomValue.generate(securityStrength, 16);
    }

    default String generateSalt(SecurityStrength securityStrength, int length) {
        return RandomValue.generate(securityStrength, length);
    }
}
