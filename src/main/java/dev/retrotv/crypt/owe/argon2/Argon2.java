package dev.retrotv.crypt.owe.argon2;

import dev.retrotv.crypt.owe.Checksum;
import dev.retrotv.crypt.owe.Password;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

/**
 * Argon2 알고리즘으로 암호화 하기 위한 {@link Password} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class Argon2 implements Password {
    private final Argon2PasswordEncoder a2pe;

    /**
     * {@link Argon2PasswordEncoder} 인스턴스를 초기화 합니다.<br>
     * 이 때, Argon2 암호화 알고리즘의 기본 설정을 사용합니다.<br>
     * <br>
     * <b>!Argon2 기본 설정</b><br>
     * saltLength: 16<br>
     * hashLength: 32<br>
     * parallelism: 1<br>
     * memory 1 {@literal <<} 14<br>
     * interations 2<br>
     */
    public Argon2() {
        a2pe = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    /**
     * {@link Argon2PasswordEncoder} 인스턴스를 초기화 합니다.<br>
     * <br>
     * <b>!매개변수 권장 값</b><br>
     * saltLength: 16<br>
     * hashLength: 32 혹은 16<br>
     * parallelism: CPU Core 수의 두 배<br>
     * memory 1 {@literal <<} 14 이상<br>
     * iterations 2 이상<br>
     * <br>
     * 공간상의 제약이 없다면 saltLength는 16, hashLength는 32로 하는 것을 권장합니다.<br>
     * 만약 공간상의 제약이 있다면, hashLength를 16으로 낮추는 것을 고려하십시오.<br>
     * <br>
     * 암호화하는 데 걸리는 시간을 조정하려면 memory와 interation 값을 조금씩 높여보면서 테스트 하십시오.<br>
     * 암호화하는 데 걸리는 시간이 길수록 안전하지만, 서비스 이용에 불편함이 생길 수 있으니 편의와 보안 간의 균형을 맞추십시오.<br>
     *
     * @param saltLength 소금의 길이 (bytes 단위)
     * @param hashLength 해시 결과물의 길이 (bytes 단위)
     * @param parallelism 스레드 개수 (클수록 안전함)
     * @param memory 암호화 시, 연산에 사용할 메모리의 크기 (클수록 안전함)
     * @param iterations 메모리에 대한 연산 반복 횟수 (클수록 안전함)
     */
    public Argon2(int saltLength, int hashLength, int parallelism, int memory, int iterations) {
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
