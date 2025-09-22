package dev.retrotv.crypto.exception;

/**
 * 암호화 또는 복호화 작업이 실패했을 때 던져지는 예외.
 *
 * @author yjj8353
 * @since 1.0.0
 */
public class CryptoFailException extends RuntimeException {

    /**
     * CryptoFailException 기본 생성자입니다.
     */
    public CryptoFailException() {
        super();
    }

    /**
     * CryptoFailException 예외 메시지를 포함하는 생성자입니다.
     *
     * @param message 예외 메시지
     */
    public CryptoFailException(String message) {
        super(message);
    }

    /**
     * CryptoFailException 예외 메시지와 원인 예외를 포함하는 생성자입니다.
     *
     * @param message 예외 메시지
     * @param cause   원인 예외
     */
    public CryptoFailException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * CryptoFailException 원인 예외를 포함하는 생성자입니다.
     *
     * @param cause 원인 예외
     */
    public CryptoFailException(Throwable cause) {
        super(cause);
    }
}
