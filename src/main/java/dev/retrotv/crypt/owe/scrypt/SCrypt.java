package dev.retrotv.crypt.owe.scrypt;

import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

/**
 * SCrypt 알고리즘으로 암호화 하기 위한 {@link Password} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class SCrypt implements Password {

    private final SCryptPasswordEncoder scrypt;

    public SCrypt() {
        scrypt = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    public SCrypt(int cpuCost, int memoryCost, int parallelization, int keyLength, int saltLength) {
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
