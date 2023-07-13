package dev.retrotv.crypt.owe.kdf.bcrypt;

import dev.retrotv.crypt.owe.kdf.KDF;
import lombok.NonNull;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.security.SecureRandom;

/**
 * BCrypt 알고리즘으로 암호화 하기 위한 {@link Password} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class BCrypt extends KDF {
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public BCrypt() {
        bCryptPasswordEncoder = new BCryptPasswordEncoder();
    }

    public BCrypt(int strength) {
        bCryptPasswordEncoder = new BCryptPasswordEncoder(strength);
    }

    public BCrypt(BCryptPasswordEncoder.BCryptVersion version) {
        bCryptPasswordEncoder = new BCryptPasswordEncoder(version);
    }

    public BCrypt(BCryptPasswordEncoder.BCryptVersion version, SecureRandom random) {
        bCryptPasswordEncoder = new BCryptPasswordEncoder(version, random);
    }

    public BCrypt(int strength, SecureRandom random) {
        bCryptPasswordEncoder = new BCryptPasswordEncoder(strength, random);
    }

    public BCrypt(BCryptPasswordEncoder.BCryptVersion version, int strength) {
        bCryptPasswordEncoder = new BCryptPasswordEncoder(version, strength);
    }

    public BCrypt(BCryptPasswordEncoder.BCryptVersion version, int strength, SecureRandom random) {
        bCryptPasswordEncoder = new BCryptPasswordEncoder(version, strength, random);
    }

    @Override
    public String encode(@NonNull CharSequence rawPassword) {
        return bCryptPasswordEncoder.encode(rawPassword);
    }

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

        return bCryptPasswordEncoder.matches(rawPassword, encodedPassword);
    }
}
