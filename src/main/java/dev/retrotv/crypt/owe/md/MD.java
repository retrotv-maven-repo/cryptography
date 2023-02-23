package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.exception.CryptFailException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD 계열의 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public abstract class MD {

    /**
     * 지정된 {@link Algorithm} 유형으로 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @exception CryptFailException 암호화가 정상적으로 진행되지 않았을 경우 발생
     * @param algorithm 암호화 시, 사용할 알고리즘
     * @param data 암호화 할 데이터
     * @return 암호화 된 데이터
     */
    protected byte[] encode(Algorithm algorithm, byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm.label());
            md.update(data);

            return md.digest();
        } catch (NoSuchAlgorithmException ignored) { }

        throw new CryptFailException("암호화가 정상적으로 진행되지 않았습니다.");
    }
}
