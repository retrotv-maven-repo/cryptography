package dev.retrotv.crypto.exception;

/**
 * 디코딩 작업이 실패했을 때 던져지는 예외.
 *
 * @author yjj8353
 * @since 1.0.0
 */
public class DecodeException extends RuntimeException {

    /**
     * DecodeException 기본 생성자입니다.
     */
    public DecodeException() {
        super();
    }

    /**
     * DecodeException 예외 메시지를 포함하는 생성자입니다.
     *
     * @param message 예외 메시지
     */
    public DecodeException(String message) {
        super(message);
    }

    /**
     * DecodeException 예외 메시지와 원인 예외를 포함하는 생성자입니다.
     *
     * @param message 예외 메시지
     * @param cause   원인 예외
     */
    public DecodeException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * DecodeException 원인 예외를 포함하는 생성자입니다.
     *
     * @param cause 원인 예외
     */
    public DecodeException(Throwable cause) {
        super(cause);
    }
}
