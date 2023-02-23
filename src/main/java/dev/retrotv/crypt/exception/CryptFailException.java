package dev.retrotv.crypt.exception;

import dev.retrotv.crypt.OneWayEncryption;

/**
 * 암복호화 시, 발생할 수 있는 오류를 처리하기 위한 예외입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class CryptFailException extends RuntimeException {
    public CryptFailException() {
        super();
    }

    public CryptFailException(String message) {
        super(message);
    }
}
