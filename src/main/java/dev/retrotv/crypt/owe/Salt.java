package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.OneWayEncryption;
import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.random.SecurityStrength;

/**
 * 단방향 암호화 시, 사용할 소금 값을 자동으로 생성하기 위한 기능성 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class Salt {

    /**
     * 단방향 암호화 시, 사용할 소금 값을 {@link SecurityStrength}, len 값을 바탕으로 소금 값을 생성하고 반환 합니다.
     *
     * @param securityStrength 보안 강도 -> {@link SecurityStrength} 참조
     * @param len 생성할 소금 값 길이
     * @return 생성된 소금 값
     */
    public static String generate(SecurityStrength securityStrength, int len) {
        return RandomValue.generate(securityStrength, len);
    }
}
