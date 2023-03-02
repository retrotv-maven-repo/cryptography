package dev.retrotv.crypt.twe;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.random.RandomValue;
import dev.retrotv.crypt.random.SecurityStrength;

/**
 * 양방향 암호화 시, 사용할 키 값을 자동으로 생성하기 위한 기능성 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class Key {

    /**
     *
     * @param algorithm 양방향 암호화 알고리즘 종류: {@link Algorithm} 참조
     * @return 생성된 키 값
     */
    public static String generate(SecurityStrength securityStrength, Algorithm algorithm) {
        int len = getKeyLength(algorithm);
        return RandomValue.generate(securityStrength, len);
    }

    private static int getKeyLength(Algorithm algorithm) {
        int len = 0;
        switch (algorithm) {
            case AES128:
                len = 16;
                break;

            case AES192:
                len = 24;
                break;

            case AES256:
                len = 32;
                break;
        }

        return len;
    }
}
