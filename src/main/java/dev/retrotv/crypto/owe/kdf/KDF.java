package dev.retrotv.crypto.owe.kdf;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 패스워드 암호화 클래스 구현을 위한 추상 클래스입니다.
 * {@link PasswordEncoder}를 상속받습니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public abstract class KDF implements PasswordEncoder {

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }

        return encodedPassword.equals(encode(rawPassword));
    }
}
