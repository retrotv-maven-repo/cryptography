package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.exception.CryptFailException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;

public interface Password extends PasswordEncoder {

    @Override
    default boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            throw new CryptFailException("비교할 password 혹은 encodedPassword 값이 null 입니다.");
        }

        return encodedPassword.equals(encode(rawPassword));
    }
}
