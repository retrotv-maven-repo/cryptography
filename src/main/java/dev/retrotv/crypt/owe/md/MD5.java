package dev.retrotv.crypt.owe.md;

import dev.retrotv.enums.Algorithm;
import dev.retrotv.utils.EncodeUtil;
import dev.retrotv.crypt.owe.MessageDigestEncrypt;
import dev.retrotv.utils.CommonMessageUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * MD5 알고리즘으로 암호화 하기 위한 {@link MessageDigestEncrypt} 추상 클래스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class MD5 extends MessageDigestEncrypt {
    private static final Logger logger = LogManager.getLogger();
    private static final CommonMessageUtil commonMessageUtil = new CommonMessageUtil();

    @Override
    public String encode(byte[] data) {
        if (data == null) {
            logger.error(commonMessageUtil.getMessage("error.parameter.null", "data"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "data"));
        }

        return EncodeUtil.binaryToHex(encode(Algorithm.MD5, data));
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            logger.error(commonMessageUtil.getMessage("error.parameter.null", "rawPassword"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "rawPassword"));
        }

        String password = String.valueOf(rawPassword);
        return encode(password.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public String encode(CharSequence rawPassword, Charset charset) {
        if (rawPassword == null) {
            logger.error(commonMessageUtil.getMessage("error.parameter.null", "rawPassword"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "rawPassword"));
        }

        String password = String.valueOf(rawPassword);
        return encode(password.getBytes(charset));
    }
}
