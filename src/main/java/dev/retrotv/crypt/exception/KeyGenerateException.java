package dev.retrotv.crypt.exception;

/**
 * 키 생성 시, 발생할 수 있는 오류를 처리하기 위한 예외입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class KeyGenerateException extends Exception {
    public KeyGenerateException() {
        super();
    }

    public KeyGenerateException(String message) {
        super(message);
    }

    public KeyGenerateException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
