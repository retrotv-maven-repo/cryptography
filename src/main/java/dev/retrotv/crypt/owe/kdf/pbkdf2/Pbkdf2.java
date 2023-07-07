package dev.retrotv.crypt.owe.kdf.pbkdf2;

import dev.retrotv.crypt.owe.Password;
import dev.retrotv.utils.CommonMessageUtil;
import lombok.NonNull;

import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

/**
 * Pbkdf2 알고리즘으로 암호화 하기 위한 {@link Password} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class Pbkdf2 implements Password {
    private final Pbkdf2PasswordEncoder pbkdf2PasswordEncoder;

    public Pbkdf2() {
        pbkdf2PasswordEncoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    public Pbkdf2(CharSequence secret, int saltLength, int iterations,
           Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm secretKeyFactoryAlgorithm) {
        pbkdf2PasswordEncoder = new Pbkdf2PasswordEncoder(secret, saltLength, iterations, secretKeyFactoryAlgorithm);
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword) {
        return pbkdf2PasswordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            log.warn("매개변수 rawPassword가 null 입니다.");
            return false;
        }

        if (encodedPassword == null) {
            log.warn("매개변수 encodedPassword가 null 입니다.");
            return false;
        }

        return pbkdf2PasswordEncoder.matches(rawPassword, encodedPassword);
    }
}
