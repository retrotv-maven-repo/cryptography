package dev.retrotv.crypto.owe.kdf.bcrypt;

import dev.retrotv.crypto.owe.kdf.KDF;
import dev.retrotv.utils.PasswordStrengthUtil;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.SecureRandom;

/**
 * BCrypt 알고리즘으로 암호화 하기 위한 {@link KDF} 추상 클래스의 구현체 입니다.
 * Spring Security의 {@link PasswordEncoder}와 호환됩니다.
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
        if (version == null) {
            throw new IllegalArgumentException("version은 null일 수 없습니다.");
        }

        bCryptPasswordEncoder = new BCryptPasswordEncoder(version);
    }

    public BCrypt(BCryptPasswordEncoder.BCryptVersion version, SecureRandom random) {
        if (version == null) {
            throw new IllegalArgumentException("version은 null일 수 없습니다.");
        }

        if (random == null) {
            throw new IllegalArgumentException("random은 null일 수 없습니다.");
        }

        bCryptPasswordEncoder = new BCryptPasswordEncoder(version, random);
    }

    public BCrypt(int strength, SecureRandom random) {
        if (random == null) {
            throw new IllegalArgumentException("random은 null일 수 없습니다.");
        }

        bCryptPasswordEncoder = new BCryptPasswordEncoder(strength, random);
    }

    public BCrypt(BCryptPasswordEncoder.BCryptVersion version, int strength) {
        if (version == null) {
            throw new IllegalArgumentException("version은 null일 수 없습니다.");
        }

        bCryptPasswordEncoder = new BCryptPasswordEncoder(version, strength);
    }

    public BCrypt(BCryptPasswordEncoder.BCryptVersion version, int strength, SecureRandom random) {
        if (version == null) {
            throw new IllegalArgumentException("version은 null일 수 없습니다.");
        }

        if (random == null) {
            throw new IllegalArgumentException("random은 null일 수 없습니다.");
        }

        bCryptPasswordEncoder = new BCryptPasswordEncoder(version, strength, random);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword는 null일 수 없습니다.");
        }

        return bCryptPasswordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }

        return bCryptPasswordEncoder.matches(rawPassword, encodedPassword);
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        if (encodedPassword == null) {
            return false;
        }

        return PasswordStrengthUtil.checkLength(8, encodedPassword) &&
               PasswordStrengthUtil.isInclude(
                   true,
                   false,
                   false,
                   true,
                   true,
                   encodedPassword
               );
	}
}
