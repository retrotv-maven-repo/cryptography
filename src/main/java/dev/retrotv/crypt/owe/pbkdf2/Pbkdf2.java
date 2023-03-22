package dev.retrotv.crypt.owe.pbkdf2;

import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

public class Pbkdf2 implements Password {
    private final Pbkdf2PasswordEncoder pbkdf2;

    Pbkdf2() {
        pbkdf2 = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    Pbkdf2(CharSequence secret, int saltLength, int iterations,
           Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm secretKeyFactoryAlgorithm) {
        pbkdf2 = new Pbkdf2PasswordEncoder(secret, saltLength, iterations, secretKeyFactoryAlgorithm);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return pbkdf2.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return pbkdf2.matches(rawPassword, encodedPassword);
    }
}
