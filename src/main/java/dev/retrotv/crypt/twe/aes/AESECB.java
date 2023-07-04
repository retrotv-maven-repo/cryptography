package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.exception.WrongKeyLengthException;

import static dev.retrotv.enums.Algorithm.AESECB;

/**
 * AES/ECB 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class AESECB extends AES {

    public AESECB(int keyLen) {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            log.debug("keyLen 값: {}", keyLen);
            throw new WrongKeyLengthException();
        }

        this.keyLen = keyLen;
        this.algorithm = AESECB;
    }
}
