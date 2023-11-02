package dev.retrotv.crypto.owe.kdf.scrypt;

import dev.retrotv.crypto.owe.kdf.KDF;
import dev.retrotv.utils.PasswordStrengthUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

/**
 * SCrypt 알고리즘으로 암호화 하기 위한 {@link KDF} 추상 클래스의 구현체 입니다.
 * Spring Security의 {@link PasswordEncoder}와 호환됩니다.
 * @author  yjj8353
 * @since   1.8
 */
public class SCrypt extends KDF {

    private final SCryptPasswordEncoder sCryptPasswordEncoder;

    public SCrypt() {
        sCryptPasswordEncoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    public SCrypt(int cpuCost, int memoryCost, int parallelization, int keyLength, int saltLength) {
        sCryptPasswordEncoder = new SCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("rawPassword는 null일 수 없습니다.");
        }

        return sCryptPasswordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null) {
            return false;
        }

        return sCryptPasswordEncoder.matches(rawPassword, encodedPassword);
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
