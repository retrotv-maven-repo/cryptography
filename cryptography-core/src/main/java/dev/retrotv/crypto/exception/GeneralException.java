package dev.retrotv.crypto.exception;

/**
 * 일반적으로 발생하지 않는 체크 예외를 언체크 예외로 변환할 때 사용하는 예외.
 *
 * @author yjj8353
 * @since 1.0.0
 */
public class GeneralException extends RuntimeException {

    /**
     * GeneralException 기본 생성자입니다.
     */
    public GeneralException() {
        super();
    }

    /**
     * GeneralException 예외 메시지를 포함하는 생성자입니다.
     *
     * @param message 예외 메시지
     */
    public GeneralException(String message) {
        super(message);
    }

    /**
     * GeneralException 예외 메시지와 원인 예외를 포함하는 생성자입니다.
     *
     * @param message 예외 메시지
     * @param cause   원인 예외
     */
    public GeneralException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * GeneralException 원인 예외를 포함하는 생성자입니다.
     *
     * @param cause 원인 예외
     */
    public GeneralException(Throwable cause) {
        super(cause);
    }
}
