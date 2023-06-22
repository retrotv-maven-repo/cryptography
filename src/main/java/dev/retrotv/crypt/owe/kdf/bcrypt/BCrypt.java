package dev.retrotv.crypt.owe.kdf.bcrypt;

import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.security.SecureRandom;

/**
 * BCrypt 알고리즘으로 암호화 하기 위한 {@link Password} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class BCrypt implements Password {
    private final BCryptPasswordEncoder bcpe;

    public BCrypt() {
        bcpe = new BCryptPasswordEncoder();
    }

    public BCrypt(int strength) {
        bcpe = new BCryptPasswordEncoder(strength);
    }

    public BCrypt(BCryptPasswordEncoder.BCryptVersion version) {
        bcpe = new BCryptPasswordEncoder(version);
    }

    public BCrypt(BCryptPasswordEncoder.BCryptVersion version, SecureRandom random) {
        bcpe = new BCryptPasswordEncoder(version, random);
    }

    public BCrypt(int strength, SecureRandom random) {
        bcpe = new BCryptPasswordEncoder(strength, random);
    }

    public BCrypt(BCryptPasswordEncoder.BCryptVersion version, int strength) {
        bcpe = new BCryptPasswordEncoder(version, strength);
    }

    public BCrypt(BCryptPasswordEncoder.BCryptVersion version, int strength, SecureRandom random) {
        bcpe = new BCryptPasswordEncoder(version, strength, random);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            logger.error(commonMessageUtil.getMessage("error.parameter.null", "rawPassword"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "rawPassword"));
        }

        return bcpe.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            logger.warn(commonMessageUtil.getMessage("warn.parameter.null", "rawPassword"));
            return false;
        }

        if (encodedPassword == null) {
            logger.warn(commonMessageUtil.getMessage("warn.parameter.null", "encodedPassword"));
            return false;
        }

        return bcpe.matches(rawPassword, encodedPassword);
    }
}
