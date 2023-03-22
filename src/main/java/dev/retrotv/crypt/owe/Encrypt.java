package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.exception.CryptFailException;

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

    /**
     * 지정된 {@link Algorithm} 유형으로 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @param algorithm 암호화 시, 사용할 알고리즘
     * @param data 암호화 할 데이터
     * @return 암호화 된 데이터
     * @throws CryptFailException data가 null 일 경우 발생
     * @throws CryptFailException 암호화가 정상적으로 진행되지 않았을 경우 발생
     */
    protected byte[] encrypt(Algorithm algorithm, byte[] data) {
        Optional.ofNullable(data).orElseThrow(() ->
                new NullPointerException("암호화 할 문자열 및 데이터가 null 입니다."));

        MessageDigest md;

        try {
            if (Algorithm.MD4.equals(algorithm)) {
                md = sun.security.provider.MD4.getInstance();
            } else {
                md = MessageDigest.getInstance(algorithm.label());
            }

            md.update(data);

            return md.digest();
        } catch (NoSuchAlgorithmException ignored) { }

        throw new RuntimeException("암호화가 정상적으로 진행되지 않았습니다.");
    }
}
