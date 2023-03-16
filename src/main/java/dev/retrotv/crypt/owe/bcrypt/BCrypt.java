package dev.retrotv.crypt.owe.bcrypt;

import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCrypt implements Password {

    @Override
    public String encode(CharSequence rawPassword) {
        BCryptPasswordEncoder bcpe = new BCryptPasswordEncoder();
        return bcpe.encode(rawPassword);
    }
}
