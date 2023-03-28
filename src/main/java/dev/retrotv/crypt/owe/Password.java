package dev.retrotv.crypt.owe;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 패스워드 암호화 클래스 구현을 위한 인터페이스 입니다.
 * {@link PasswordEncoder}를 상속받습니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public interface Password extends PasswordEncoder {

    @Override
    default boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            throw new NullPointerException("비교할 password 혹은 encodedPassword 값이 null 입니다.");
        }

        return encodedPassword.equals(encode(rawPassword));
    }
}
