package dev.retrotv.crypt.owe.argon2;

import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

public class Argon2 implements Password {
    private final Argon2PasswordEncoder a2pe;

    Argon2() {
        final int saltLength = 16;
        final int hashLength = 32;
        final int parallelism = 1;
        final int memory = 1 << 14;
        final int iterations = 2;

        a2pe = new Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations);
    }

    Argon2(int saltLength, int hashLength, int parallelism, int memory, int iterations) {
        a2pe = new Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return a2pe.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return a2pe.matches(rawPassword, encodedPassword);
    }
}
