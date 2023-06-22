package dev.retrotv.crypt.owe.kdf.pbkdf2;

import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

/**
 * Pbkdf2 알고리즘으로 암호화 하기 위한 {@link Password} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class Pbkdf2 implements Password {
    private final Pbkdf2PasswordEncoder pbkdf2;

    public Pbkdf2() {
        pbkdf2 = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    public Pbkdf2(CharSequence secret, int saltLength, int iterations,
           Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm secretKeyFactoryAlgorithm) {
        pbkdf2 = new Pbkdf2PasswordEncoder(secret, saltLength, iterations, secretKeyFactoryAlgorithm);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            logger.error(COMMON_MESSAGE.getMessage("error.parameter.null", "rawPassword"));
            throw new NullPointerException(COMMON_MESSAGE.getMessage("exception.nullPointer", "rawPassword"));
        }

        return pbkdf2.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            logger.warn(COMMON_MESSAGE.getMessage("warn.parameter.null", "rawPassword"));
            return false;
        }

        if (encodedPassword == null) {
            logger.warn(COMMON_MESSAGE.getMessage("warn.parameter.null", "encodedPassword"));
            return false;
        }

        return pbkdf2.matches(rawPassword, encodedPassword);
    }
}
