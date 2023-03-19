package dev.retrotv.crypt.owe.argon2;

import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;

public class Argon2 implements Password {
    private final int saltlength;
    private final int hashLength;
    private final int parallelism;
    private final int memory;
    private final int iterations;

    Argon2() {
        this.saltlength = 16;
        this.hashLength = 32;
        this.parallelism = 1;
        this.memory = 1 << 14;
        this.iterations = 2;
    }

    Argon2(int saltLength, int hashLength, int parallelism, int memory, int iterations) {
        this.saltlength = saltLength;
        this.hashLength = hashLength;
        this.parallelism = parallelism;
        this.memory = memory;
        this.iterations = iterations;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        Argon2PasswordEncoder a2pe = new Argon2PasswordEncoder(saltlength, hashLength, parallelism, memory, iterations);
        return a2pe.encode(rawPassword);
    }
}
