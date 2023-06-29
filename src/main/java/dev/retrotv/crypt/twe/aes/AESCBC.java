package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.enums.SecurityStrength;

/**
 * AES/CBC 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public abstract class AESCBC extends AES {

    /**
     * AES/CBC 알고리즘에서 사용할 초기화 벡터 값을 생성합니다.
     *
     * @param securityStrength 보안 강도: {@link SecurityStrength} 참조
     * @return 생성된 초기화 벡터
     */
    public byte[] generateInitializationVector(SecurityStrength securityStrength) {
        RandomValue rv = new RandomValue();
        rv.generate(securityStrength, 16);
        return rv.getBytes();
    }
}
