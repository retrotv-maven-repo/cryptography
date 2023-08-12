package dev.retrotv.crypto.owe.hash;

import lombok.NonNull;

import org.springframework.security.crypto.password.PasswordEncoder;

import dev.retrotv.utils.PasswordStrengthUtil;

import java.nio.charset.Charset;

/**
 * 소금을 이용한 패스워드 암호화 클래스 구현을 위한 인터페이스 입니다.
 * {@link PasswordEncoder}를 상속받습니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public interface PasswordWithSalt extends PasswordEncoder {

    @Override
    String encode(@NonNull CharSequence rawPassword);

    /**
     * 패스워드를 암호화 한 뒤, 암호화 된 패스워드를 지정된 캐릭터 셋으로 변환한 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @return 암호화 된 패스워드 문자열
     */
    String encode(@NonNull CharSequence rawPassword, @NonNull Charset charset);

    /**
     * 패스워드에 소금을 치고 암호화 한 뒤, 암호화 된 패스워드 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @return 암호화 된 패스워드 문자열
     */
    String encode(@NonNull CharSequence rawPassword, CharSequence salt);

    /**
     * 패스워드에 소금을 치고 암호화 한 뒤, 암호화 된 패스워드 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @param charset 인코딩 시 사용할 문자열 셋
     * @return 암호화 된 패스워드 문자열
     */
    String encode(@NonNull CharSequence rawPassword, CharSequence salt, Charset charset);

    @Override
    boolean matches(CharSequence rawPassword, String encodedPassword);

    /**
     * 패스워드에 소금을 치고 암호화 된 문자열을 비교할 암호화 된 문자열과 비교 후, 일치 여부를 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @param encodedPassword 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    boolean matches(CharSequence rawPassword, CharSequence salt, String encodedPassword);

    @Override
    default boolean upgradeEncoding(String encodedPassword) {
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
