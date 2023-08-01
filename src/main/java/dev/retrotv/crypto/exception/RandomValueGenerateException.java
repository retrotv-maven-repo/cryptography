package dev.retrotv.crypto.exception;

/**
 * 무작위 값 생성 시, 발생할 수 있는 오류를 처리하기 위한 예외입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class RandomValueGenerateException extends RuntimeException {
    public RandomValueGenerateException() {
        super();
    }

    public RandomValueGenerateException(String message) {
        super(message);
    }

    public RandomValueGenerateException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
