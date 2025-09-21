package dev.retrotv.crypto.exception;

/**
 * 알고리즘을 찾을 수 없을 때 던져지는 예외.
 *
 * @author yjj8353
 * @since 1.0.0
 */
public class AlgorithmNotFoundException extends IllegalArgumentException {

    /**
     * AlgorithmNotFoundException 기본 생성자입니다.
     */
    public AlgorithmNotFoundException() {
        super();
    }

    /**
     * AlgorithmNotFoundException 예외 메시지를 포함하는 생성자입니다.
     *
     * @param message 예외 메시지
     */
    public AlgorithmNotFoundException(String message) {
        super(message);
    }

    /**
     * AlgorithmNotFoundException 예외 메시지와 원인 예외를 포함하는 생성자입니다.
     *
     * @param message 예외 메시지
     * @param cause   원인 예외
     */
    public AlgorithmNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * AlgorithmNotFoundException 원인 예외를 포함하는 생성자입니다.
     *
     * @param cause 원인 예외
     */
    public AlgorithmNotFoundException(Throwable cause) {
        super(cause);
    }
}
