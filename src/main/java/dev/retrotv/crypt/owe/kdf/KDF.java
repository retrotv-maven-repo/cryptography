package dev.retrotv.crypt.owe.kdf;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 패스워드 암호화 클래스 구현을 위한 추상 클래스입니다.
 * {@link PasswordEncoder}를 상속받습니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public abstract class KDF implements PasswordEncoder {
    protected static final Logger log = LogManager.getLogger();

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

        return encodedPassword.equals(encode(rawPassword));
    }
}