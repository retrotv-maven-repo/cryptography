package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.owe.MessageDigestEncrypt;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.crypt.Encode;
import dev.retrotv.crypt.owe.Checksum;
import dev.retrotv.crypt.owe.PasswordWithSalt;
import dev.retrotv.utils.CommonMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.Charset;

/**
 * SHA-512 알고리즘으로 암호화 하기 위한 {@link Checksum}, {@link PasswordWithSalt} 인터페이스의 구현체 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class SHA512 extends MessageDigestEncrypt implements Checksum, PasswordWithSalt {
    private static final Logger logger = LogManager.getLogger();
    private static final CommonMessage commonMessage = new CommonMessage();

    @Override
    public String encode(byte[] data) {
        if (data == null) {
            logger.error(commonMessage.getMessage("error.parameter.null", "data"));
            throw new NullPointerException(commonMessage.getMessage("exception.nullPointer", "data"));
        }

        return Encode.binaryToHex(encode(Algorithm.SHA512, data));
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            logger.error(commonMessage.getMessage("error.parameter.null", "rawPassword"));
            throw new NullPointerException(commonMessage.getMessage("exception.nullPointer", "rawPassword"));
        }

        String password = String.valueOf(rawPassword);
        return encode(password.getBytes());
    }

    @Override
    public String encode(CharSequence rawPassword, Charset charset) {
        if (rawPassword == null) {
            logger.error(commonMessage.getMessage("error.parameter.null", "rawPassword"));
            throw new NullPointerException(commonMessage.getMessage("exception.nullPointer", "rawPassword"));
        }

        String password = String.valueOf(rawPassword);
        return encode(password.getBytes(charset));
    }
}
