package dev.retrotv.crypto.exception;

/**
 * 키 또는 초기화 벡터(IV) 생성이 실패했을 때 던져지는 예외.
 *
 * @author yjj8353
 * @since 1.0.0
 */
public class GenerateException extends RuntimeException {

    /**
     * GenerateException 기본 생성자입니다.
     */
    public GenerateException() {
        super();
    }

    /**
     * GenerateException 예외 메시지를 포함하는 생성자입니다.
     *
     * @param message 예외 메시지
     */
    public GenerateException(String message) {
        super(message);
    }

    /**
     * GenerateException 예외 메시지와 원인 예외를 포함하는 생성자입니다.
     *
     * @param message 예외 메시지
     * @param cause   원인 예외
     */
    public GenerateException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * GenerateException 원인 예외를 포함하는 생성자입니다.
     *
     * @param cause 원인 예외
     */
    public GenerateException(Throwable cause) {
        super(cause);
    }
}
