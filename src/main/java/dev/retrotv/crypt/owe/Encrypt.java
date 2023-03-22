package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.Algorithm;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

/**
 * {@link MessageDigest}를 사용하는 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author yjj8353
 * @since 1.8
 */
public class Encrypt {
    private static final String WARNING_MESSAGE =
            "이 예외는 기본적으로 발생하지 않습니다, 발생한다면 다음 사항을 확인하십시오."
          + "\n1. 빌드 한 JAVA version에서 지원하지 않는 MessageDigest 알고리즘을 사용하는지 확인하십시오."
          + "\n2. MessageDigest를 사용하지 않는 암호화 알고리즘의 경우, 해당 암호화 로직이 정상적으로 동작하는지 확인하십시오.";

    /**
     * 지정된 {@link Algorithm} 유형으로 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @param algorithm 암호화 시, 사용할 알고리즘
     * @param data 암호화 할 데이터
     * @return 암호화 된 데이터
     */
    protected byte[] encrypt(Algorithm algorithm, byte[] data) {
        Optional.ofNullable(data).orElseThrow(() ->
                new NullPointerException("암호화 할 문자열 및 데이터가 null 입니다."));

        MessageDigest md;

        try {
            md = MessageDigest.getInstance(algorithm.label());
            md.update(data);

            return md.digest();
        } catch (NoSuchAlgorithmException ignored) { }

        throw new RuntimeException(WARNING_MESSAGE);
    }
}
