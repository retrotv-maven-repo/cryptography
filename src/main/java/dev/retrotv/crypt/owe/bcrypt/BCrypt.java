package dev.retrotv.crypt.owe.bcrypt;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class BCrypt {

    public String encrypt(String text) {
        BCryptPasswordEncoder bcpe = new BCryptPasswordEncoder();
        return bcpe.encode(text);
    }
}
