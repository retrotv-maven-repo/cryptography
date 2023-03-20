package dev.retrotv.crypt.owe.bcrypt;

import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCrypt implements Password {
    private final BCryptPasswordEncoder bcpe;

    BCrypt() {
        bcpe = new BCryptPasswordEncoder();
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return bcpe.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return bcpe.matches(rawPassword, encodedPassword);
    }
}
