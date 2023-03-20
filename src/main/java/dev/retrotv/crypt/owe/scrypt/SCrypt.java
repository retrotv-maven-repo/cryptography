package dev.retrotv.crypt.owe.scrypt;

import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

public class SCrypt implements Password {

    private final SCryptPasswordEncoder scrypt;

    SCrypt() {
        scrypt = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    SCrypt(int cpuCost, int memoryCost, int parallelization, int keyLength, int saltLength) {
        scrypt = new SCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return scrypt.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return scrypt.matches(rawPassword, encodedPassword);
    }
}
