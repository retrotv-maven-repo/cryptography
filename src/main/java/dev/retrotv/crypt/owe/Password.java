package dev.retrotv.crypt.owe;

import dev.retrotv.utils.CommonMessageUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 패스워드 암호화 클래스 구현을 위한 인터페이스 입니다.
 * {@link PasswordEncoder}를 상속받습니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public interface Password extends PasswordEncoder {
    Logger logger = LogManager.getLogger();
    CommonMessageUtil commonMessageUtil = new CommonMessageUtil();

    @Override
    default boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            logger.warn(commonMessageUtil.getMessage("warn.parameter.null", "rawPassword"));
            return false;
        }

        if (encodedPassword == null) {
            logger.warn(commonMessageUtil.getMessage("warn.parameter.null", "encodedPassword"));
            return false;
        }

        return encodedPassword.equals(encode(rawPassword));
    }
}
