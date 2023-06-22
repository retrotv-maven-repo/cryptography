package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.enums.SecurityStrength;
import dev.retrotv.utils.CommonMessageUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.Charset;

/**
 * 소금을 이용한 패스워드 암호화 클래스 구현을 위한 인터페이스 입니다.
 * 키 유도 함수를 자체적으로 포함하고 있는 암호화 알고리즘을 사용할 경우 {@link Password} 인터페이스를 상속받아 구현하십시오.
 * {@link Password}를 상속받습니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public interface PasswordWithSalt extends Password {
    Logger logger = LogManager.getLogger();
    CommonMessageUtil commonMessageUtil = new CommonMessageUtil();

    String encode(CharSequence rawPassword, Charset charset);

    /**
     * 패스워드에 소금을 치고 암호화 한 뒤, 암호화 된 패스워드 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @return 암호화 된 패스워드 문자열
     */
    default String encode(CharSequence rawPassword, CharSequence salt) {
        if (rawPassword == null) {
            logger.error(commonMessageUtil.getMessage("error.parameter.null", "rawPassword"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "rawPassword"));
        }

        if (salt == null) {
            logger.warn(commonMessageUtil.getMessage("warn.parameter.null", "salt"));
            logger.warn("의도한 것이 아니라면 encode(CharSequence rawPassword) 메소드를 사용하십시오.");
        }

        return encode(String.valueOf(rawPassword) + salt);
    }

    /**
     * 패스워드에 소금을 치고 암호화 한 뒤, 암호화 된 패스워드 문자열을 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @param charset 인코딩 시 사용할 문자열 셋
     * @return 암호화 된 패스워드 문자열
     */
    default String encode(CharSequence rawPassword, CharSequence salt, Charset charset) {
        if (rawPassword == null) {
            logger.error(commonMessageUtil.getMessage("error.parameter.null", "rawPassword"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "rawPassword"));
        }

        if (salt == null) {
            logger.warn(commonMessageUtil.getMessage("warn.parameter.null", "salt"));
            logger.warn("의도한 것이 아니라면 encode(CharSequence rawPassword) 메소드를 사용하십시오.");
        }

        return encode(String.valueOf(rawPassword) + salt, charset);
    }

    /**
     * 패스워드에 소금을 치고 암호화 된 문자열을 비교할 암호화 된 문자열과 비교 후, 일치 여부를 반환합니다.
     *
     * @param rawPassword 암호화 할 패스워드
     * @param salt 소금
     * @param encodedPassword 비교할 암호화 된 문자열
     * @return 일치 여부
     */
    default boolean matches(CharSequence rawPassword, CharSequence salt, String encodedPassword) {
        if (rawPassword == null) {
            logger.warn(commonMessageUtil.getMessage("warn.parameter.null", "rawPassword"));
            return false;
        }

        if (encodedPassword == null) {
            logger.warn(commonMessageUtil.getMessage("warn.parameter.null", "encodedPassword"));
            return false;
        }

        if (salt == null) {
            logger.warn(commonMessageUtil.getMessage("warn.parameter.null", "salt"));
            logger.warn("의도한 것이 아니라면 matches(CharSequence rawPassword, String encodedPassword) 메소드를 사용하십시오.");
        }

        return matches(String.valueOf(rawPassword) + salt, encodedPassword);
    }

    /**
     * 소금을 생성하고 반환합니다.
     * 보안 강도와 소금의 길이는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @return 생성된 소금
     */
    default String generateSalt() {
        RandomValue rv = new RandomValue();
        rv.generate();
        return rv.getValue();
    }

    /**
     * len 만큼의 길이를 가진 소금을 생성하고 반환합니다.
     * 보안 강도는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @param len 생성할 소금의 길이
     * @return 생성된 소금
     */
    default String generateSalt(int len) {
        RandomValue rv = new RandomValue();
        rv.generate(len);
        return rv.getValue();
    }

    /**
     * securityStrength 수준의 소금을 생성하고 반환합니다.
     * 소금의 길이는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @param securityStrength 보안 강도, {@link SecurityStrength} 참조
     * @return 생성된 소금
     */
    default String generateSalt(SecurityStrength securityStrength) {
        RandomValue rv = new RandomValue();
        rv.generate(securityStrength);
        return rv.getValue();
    }

    /**
     * securityStrength의 수준과 len 만큼의 길이를 가진 소금을 생성하고 반환합니다.
     *
     * @param securityStrength 보안 강도, {@link SecurityStrength} 참조
     * @param length 생성할 소금의 길이
     * @return 생성된 소금
     */
    default String generateSalt(SecurityStrength securityStrength, int length) {
        RandomValue rv = new RandomValue();
        rv.generate(securityStrength, length);
        return rv.getValue();
    }
}
