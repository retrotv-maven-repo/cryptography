package dev.retrotv.crypto.twe.aes;

import dev.retrotv.crypto.exception.WrongKeyLengthException;

import static dev.retrotv.enums.CipherAlgorithm.AESECB;

/**
 * AES/ECB 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class AESECB extends AES {

    public AESECB(int keyLen) {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            throw new WrongKeyLengthException();
        }

        this.keyLen = keyLen;
        this.algorithm = AESECB;
    }
}
