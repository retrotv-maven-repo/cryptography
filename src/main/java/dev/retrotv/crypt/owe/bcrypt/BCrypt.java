package dev.retrotv.crypt.owe.bcrypt;

import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.security.SecureRandom;

public class BCrypt implements Password {
    private final BCryptPasswordEncoder bcpe;

    BCrypt() {
        bcpe = new BCryptPasswordEncoder();
    }

    BCrypt(int strength) {
        bcpe = new BCryptPasswordEncoder(strength);
    }

    BCrypt(BCryptPasswordEncoder.BCryptVersion version) {
        bcpe = new BCryptPasswordEncoder(version);
    }

    BCrypt(BCryptPasswordEncoder.BCryptVersion version, SecureRandom random) {
        bcpe = new BCryptPasswordEncoder(version, random);
    }

    BCrypt(int strength, SecureRandom random) {
        bcpe = new BCryptPasswordEncoder(strength, random);
    }

    BCrypt(BCryptPasswordEncoder.BCryptVersion version, int strength) {
        bcpe = new BCryptPasswordEncoder(version, strength);
    }

    BCrypt(BCryptPasswordEncoder.BCryptVersion version, int strength, SecureRandom random) {
        bcpe = new BCryptPasswordEncoder(version, strength, random);
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
