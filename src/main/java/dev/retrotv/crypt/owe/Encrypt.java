package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.Algorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * {@link MessageDigest}를 사용하는 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author yjj8353
 * @since 1.8
 */
public class Encrypt {
    private final Logger logger = LogManager.getLogger();

    private static final String ENCRYPT_FAIL_MESSAGE = "암호화가 정상적으로 이루어지지 않았습니다.";

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
            logger.error(ENCRYPT_FAIL_MESSAGE);
            throw new NullPointerException("algorithm이 null 입니다.");
        }

        if (data == null) {
            logger.error(ENCRYPT_FAIL_MESSAGE);
            throw new NullPointerException("data가 null 입니다.");
        }

        try {
            logger.debug("알고리즘: {}", algorithm.label());
            MessageDigest md = MessageDigest.getInstance(algorithm.label());
            md.update(data);

            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            logger.error(ENCRYPT_FAIL_MESSAGE);
            throw new RuntimeException(WARNING_MESSAGE);
        }
    }
}
