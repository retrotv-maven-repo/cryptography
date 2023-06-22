package dev.retrotv.crypt.owe;

import dev.retrotv.enums.Algorithm;
import dev.retrotv.utils.CommonMessageUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * {@link MessageDigest}를 사용하는 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author yjj8353
 * @since 1.8
 */
public abstract class MessageDigestEncrypt implements Checksum, PasswordWithSalt  {
    protected static final Logger log = LogManager.getLogger();
    protected static final CommonMessageUtil commonMessageUtil = new CommonMessageUtil();

    private static final String WARNING_MESSAGE =
            "이 예외는 기본적으로 발생하지 않습니다, 만약 예외가 발생한다면 다음 사항을 확인하십시오."
          + "\n1. 빌드 한 JAVA version에서 지원하지 않는 MessageDigest 알고리즘을 사용하는지 확인하십시오."
          + "\n2. MessageDigest를 사용하지 않는 암호화 알고리즘의 경우, 해당 암호화 로직이 정상적으로 동작하는지 확인하십시오.";

    /**
     * 지정된 {@link Algorithm} 유형으로 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @param algorithm 암호화 시, 사용할 알고리즘
     * @param data 암호화 할 데이터
     * @return 암호화 된 데이터
     */
    protected byte[] encode(Algorithm algorithm, byte[] data) {
        if (algorithm == null) {
            log.error(commonMessageUtil.getMessage("error.parameter.null", "algorithm"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "algorithm"));
        }

        if (data == null) {
            log.error(commonMessageUtil.getMessage("error.parameter.null", "data"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "data"));
        }

        try {
            log.debug("알고리즘: {}", algorithm.label());
            MessageDigest md = MessageDigest.getInstance(algorithm.label());
            md.update(data);

            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            log.error(commonMessageUtil.getMessage("exception.encryptFail"));
            throw new RuntimeException(WARNING_MESSAGE);
        }
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            log.error(commonMessageUtil.getMessage("error.parameter.null", "rawPassword"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "rawPassword"));
        }

        String password = String.valueOf(rawPassword);
        return encode(password.getBytes());
    }

    @Override
    public String encode(CharSequence rawPassword, Charset charset) {
        if (rawPassword == null) {
            log.error(commonMessageUtil.getMessage("error.parameter.null", "rawPassword"));
            throw new NullPointerException(commonMessageUtil.getMessage("exception.nullPointer", "rawPassword"));
        }

        String password = String.valueOf(rawPassword);
        return encode(password.getBytes(charset));
    }
}
